const fs = require('node:fs');
const readline = require('node:readline');
const path = require('node:path');
const awsCidrs = require('./public-ip-ranges/aws-cidrs');
const fastlyCidrs = require('./public-ip-ranges/fastly-cidrs');
const {
	initialiseCidrCache,
	extractIpAddressesFromSplunkData,
	processCompanyLookup
} = require('./lib/utils');

const knownCompanyCidrs = {
	Amazon: [...awsCidrs],
	Fastly: [...fastlyCidrs]
};
const whoisIpCompanyCache = new Map();
const companyCidrCache = new Map();
const batchSize = 20;

/**
 * @description - Perform WHOIS lookup with caching
 * @param {string} filePath - An IP address to execute WHOIS lookup
 * @returns {Promise<{[key: string]: string}>} - A sorted object of companies and percentage of Heroku traffic attributed to them
 */
async function herokuTrafficAnalyser(filePath) {
	console.time('Total execution time');

	if (!fs.existsSync(filePath)) {
		console.error(`File does not exist: ${filePath}`);
		process.exit(1);
	}

	console.log('🧰 Initialising CIDR cache with known ranges...');
	initialiseCidrCache(knownCompanyCidrs, companyCidrCache);

	// extract and count IPs using read streams
	console.log('📖 Reading data file and counting IP addresses...');
	const ipAddressMap = new Map();
	let eventCount = 0;

	const fileStream = fs.createReadStream(filePath);
	const lines = readline.createInterface({
		input: fileStream,
		crlfDelay: Infinity
	});

	for await (const line of lines) {
		eventCount++;
		const ipAddresses = extractIpAddressesFromSplunkData(line);

		if (ipAddresses) {
			ipAddresses.forEach((ip) => {
				ipAddressMap.set(ip, (ipAddressMap.get(ip) || 0) + 1);
			});
		}
	}

	const uniqueIpCount = ipAddressMap.size;

	console.log(
		`📊 Found ${uniqueIpCount} unique IP addresses in ${eventCount} events`
	);

	// process IP addresses with a company lookup
	const companyTrafficMap = await processCompanyLookup(
		ipAddressMap,
		batchSize,
		companyCidrCache,
		whoisIpCompanyCache
	);

	// calculate percentages per company
	const totalRequests = Array.from(ipAddressMap.values()).reduce(
		(sum, count) => sum + count,
		0
	);

	const companyPercentages = Array.from(companyTrafficMap.entries())
		.map(([company, count]) => [
			company,
			((count / totalRequests) * 100).toFixed(2)
		])
		.sort((a, b) => parseFloat(b[1]) - parseFloat(a[1]))
		.reduce((acc, [key, value]) => {
			acc[key] = value + ' %';
			return acc;
		}, {});

	console.log('\n🎉 Heroku Traffic Analyser Complete');
	console.timeEnd('Total execution time');
	console.log('📈 Cache statistics:');
	console.log(` - WHOIS cache entries: ${whoisIpCompanyCache.size}`);
	console.log(` - CIDR cache entries: ${companyCidrCache.size}`);

	return companyPercentages;
}

const dataFilePath = path.resolve(__dirname, 'splunk-data.txt');

// run the analysis
herokuTrafficAnalyser(dataFilePath).then((result) => {
	console.log('\n✅ Traffic breakdown by company:');
	console.table(result);
});
