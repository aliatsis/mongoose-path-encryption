var crypto = require('crypto');
var extend = require('extend');

var DEFAULT_OPTIONS = {
    encryptionAlgorithm: 'aes-256-cbc',
    ivLength: 16,
    // version: '00000',
    middleware: true, // allow for skipping middleware with false
    decryptPostSave: true // allow for skipping the decryption after save for improved performance
};

var INVALID_QUERY_CONDITIONALS = ['$gt', '$gte', '$lt', '$lte'];

module.exports = function(schema, options) {
    options = extend({}, DEFAULT_OPTIONS, options); // make copy to be safe
    options.paths = toStringArray(options.paths);
    options.excludedPaths = toStringArray(options.excludedPaths).concat([
        'id',
        '_id',
        schema.options.versionKey,
        schema.options.discriminatorKey
    ]);

    if (options.secret) {
        options.secret = drop256(deriveKey(options.secret, 'enc'));
    } else {
        throw new Error('Missing required secret key');
    }

    if (!options.paths.length) {
        options.paths = Object.keys(schema.paths);
    }

    options.paths = options.paths.filter(function(p) {
        return !~options.excludedPaths.indexOf(p);
    });

    if (options.middleware) { // defaults to true

        options.paths.forEach(function(p) {
            var pathSchema = schema.paths[p];
            pathSchema.castForQuery = castForQueryOverride.bind(pathSchema, pathSchema.castForQuery, options, p);
        });

        schema.pre('init', function(next, data) {
            var self = this;

            try {
                if (data) {
                    if (Array.isArray(data)) {
                        console.error('Received Array data in pre init hook');
                        throw new Error('Received Array data in pre init hook');
                    }

                    options.paths.filter(function(p) {
                        return self.isSelected(p);
                    }).map(function(p) {
                        return p.split('.');
                    }).forEach(function(ep) {
                        var lastIndex = ep.length - 1;
                        var lastObjectRef;

                        var valueForPath = ep.reduce(function(prev, curr, i) {
                            if (i === lastIndex) {
                                lastObjectRef = prev;
                            }

                            if (isTrueObject(prev)) {
                                return prev[curr];
                            }
                        }, data);

                        if (isTrueObject(lastObjectRef)) {
                            lastObjectRef[ep[lastIndex]] = decryptValue(valueForPath, options);
                        }
                    });
                }
                next();
            } catch (e) {
                next(e);
            }
        });

        schema.pre('save', function(next) {
            var self = this;

            options.paths.forEach(function(p) {
                var origSetters = schema.paths[p].setters;
                schema.paths[p].setters = [];
                self.set(p, encryptValue(self.get(p), options), Buffer);
                schema.paths[p].setters = origSetters;
            });

            next();
        });
    }


    // Encryption Instance Methods //

    schema.methods.encrypt = function() {

    };

    schema.methods.decrypt = function() {

    };

};

function castForQueryOverride(origFn, options, p, $conditional) {
    if ($conditional && ~INVALID_QUERY_CONDITIONALS.indexOf($conditional)) {
        throw new Error("Can't use " + $conditional + ' with encrypted path "' + p + '".');
    }

    var val = origFn.apply(this, arguments);

    if (Array.isArray(val)) {
        return val.map(function(v) {
            return encryptValue(v, options);
        });
    } else {
        return encryptValue(val, options);
    }
}

function encryptValue(value, options) {
    if (!hasValue(value)) {
        return value;
    }

    try {
        var iv = crypto.randomBytes(options.ivLength);
        var cipher = crypto.createCipheriv(options.encryptionAlgorithm, options.secret, iv);
        var jsonBuffer = new Buffer(JSON.stringify(value));
        var encrypted = Buffer.concat([cipher.update(jsonBuffer), cipher.final()]);

        // return Buffer.concat([options.version, iv, encrypted]);
        return Buffer.concat([iv, encrypted]);
    } catch (e) {
        throw new Error('Error while encrypting value. ' + e.name + ': ' + e.message);
    }
}

function decryptValue(encrypted, options) {
    var iv, encryptedContent, decipher, decrypted, decryptedJSON;

    if (!encrypted) {
        return encrypted;
    }

    encrypted = encrypted.buffer;

    try {
        // iv = encrypted.slice(options.version.length, options.version.length + options.ivLength);
        // version = encrypted.slice(0, options.version.length);
        iv = encrypted.slice(0, options.ivLength);
        encryptedContent = encrypted.slice(options.ivLength);
        decipher = crypto.createDecipheriv(options.encryptionAlgorithm, options.secret, iv);
        decrypted = decipher.update(encryptedContent, undefined, 'utf8') + decipher.final('utf8');
    } catch (e) {
        throw new Error('Error while decrypting value. ' + e.name + ': ' + e.message);
    }

    try {
        decryptedJSON = JSON.parse(decrypted);
    } catch (e) {
        throw new Error('Error parsing decrypted JSON. ' + e.name + ': ' + e.message);
    }

    return decryptedJSON;
}

function hasValue(val) {
    return !!val || val === 0;
}

function isTrueObject(val) {
    return val && typeof val === 'object';
}

function toStringArray(val) {
    var result = Array.isArray(val) ? val : val && [val] || [];

    result.forEach(function(s) {
        if (typeof s !== 'string') {
            throw new Error('Each path must be a string value: got ' + s);
        }
    });

    return result;
}

var deriveKey = function(master, type) {
    var hmac = crypto.createHmac('sha512', master);
    hmac.update(type);
    return new Buffer(hmac.digest());
};

var clearBuffer = function(buf) {
    for (var i = 0; i < buf.length; i++) {
        buf[i] = 0;
    }
};

var drop256 = function(buf) {
    var buf256 = new Buffer(32);
    buf.copy(buf256, 0, 0, 32);
    clearBuffer(buf);
    return buf256;
};