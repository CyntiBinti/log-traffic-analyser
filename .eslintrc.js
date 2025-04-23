module.exports = {
	extends: ['js/recommended', 'plugin:prettier/recommended'],
	parser: '@babel/eslint-parser',
	parserOptions: {
		requireConfigFile: false,
		sourceType: 'script'
	},
	plugins: ['prettier'],
	rules: {
		'prettier/prettier': 'error',
		quotes: 0,
		'space-before-function-paren': 0
	},
	ignorePatterns: ['tmp/**']
};