module.exports = {
	extends: [
		'js/recommended',
		'plugin:prettier/recommended',
		'plugin:jsdoc/recommended'
	],
	parser: '@babel/eslint-parser',
	parserOptions: {
		requireConfigFile: false,
		sourceType: 'script'
	},
	plugins: ['prettier', 'jsdoc'],
	rules: {
		indent: 'off',
		'jsdoc/check-access': 'error',
		'jsdoc/no-undefined-types': ['error', { definedTypes: ['Iterable'] }],
		'jsdoc/require-description-complete-sentence': 'off',
		'jsdoc/require-jsdoc': 'off',
		'jsdoc/require-param-description': 'off',
		'jsdoc/require-returns-description': 'off',
		'jsdoc/tag-lines': ['warn', 'any', { startLines: 1 }],
		'prettier/prettier': 'error',
		quotes: 0,
		'space-before-function-paren': 0
	}
};