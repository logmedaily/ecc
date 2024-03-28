module.exports = {
    coverageProvider: 'v8',

    coverageDirectory: 'coverage',

    moduleFileExtensions: ['js', 'json'],

    testEnvironment: 'node',

    testMatch: [
        '**/__tests__/**/*.[jt]s?(x)',
        '**/?(*.)+(spec|test).[tj]s?(x)'
    ],

    testPathIgnorePatterns: [
        '/node_modules/'
    ],

    watchman: false,
};