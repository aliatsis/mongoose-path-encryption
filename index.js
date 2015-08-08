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
    var explodedPaths = [];

    options = extend({}, DEFAULT_OPTIONS, options); // make copy to be safe
    options.paths = toStringArray(options.paths);
    options.excludedPaths = toStringArray(options.excludedPaths).concat([
        'id',
        '_id',
        schema.options.versionKey,
        schema.options.discriminatorKey
    ]);

    if (!options.secret) {
        throw new Error('Missing required secret key');
    }

    if (!options.paths.length) {
        options.paths = Object.keys(schema.paths);
    }

    options.paths = options.paths.filter(function(p) {
        return !~options.excludedPaths.indexOf(p);
    });

    explodedPaths = options.paths.map(function(p) {
        return p.split('.');
    });

    if (options.middleware) { // defaults to true

        options.paths.forEach(function(p) {
            var pathSchema = schema.paths[p];
            pathSchema.castForQuery = castForQueryOverride.bind(pathSchema, pathSchema.castForQuery, options, p);
        });

        schema.pre('init', function(next, data) {
            try {
                if (data) {
                    if (Array.isArray(data)) {
                        console.error('Received Array data in pre init hook');
                        throw new Error('Received Array data in pre init hook');
                    }

                    explodedPaths.forEach(function(ep) {
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
                self.set(p, encryptValue(self.get(p)));
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
        var jsonToEncrypt = JSON.stringify(value);
        var encrypted = cipher.update(jsonToEncrypt, 'utf8') + cipher.final();

        // return Buffer.concat([options.version, iv, encrypted]);
        return Buffer.concat([iv, encrypted]);
    } catch (e) {
        throw new Error('Error while encrypting value. ' + e.name + ': ' + e.message);
    }
}

function decryptValue(encrypted, options) {
    var iv, encryptedContent, decipher, decrypted, decryptedJSON;

    if (!hasValue(encrypted)) {
        return encrypted;
    }

    try {
        // iv = encrypted.slice(options.version.length, options.version.length + options.ivLength);
        // version = encrypted.slice(0, options.version.length);
        iv = encrypted.slice(0, options.ivLength);
        encryptedContent = encrypted.slice(options.ivLength);
        decipher = crypto.createDecipheriv(options.encryptionAlgorithm, options.secret, iv);
        decrypted = decipher.update(encryptedContent, 'hex', 'utf8') + decipher.final('utf8');
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
    var result = Array.isArray() ? val : val && [val] || [];

    result.forEach(function(s) {
        if (typeof s !== 'string') {
            throw new Error('Each path must be a string value: got ' + s);
        }
    });

    return result;
}