const ipaddr = require('ipaddr.js');
const util = require('util');
const { exec } = require('node:child_process');
const execAsync = util.promisify(exec);

/**
 * @description - Initialise CIDR cache with known company CIDR ranges
 * @param {{[key: string]: string[]}} knownCompanyCidrs - An object of known company CIDR ranges
 * @param {Map<string, string>} companyCidrCache - A cache of company CIDRs
 * @returns {void}
 */
exports.initialiseCidrCache = function initialiseCidrCache(
	knownCompanyCidrs,
	companyCidrCache
) {
	for (const [company, cidrs] of Object.entries(knownCompanyCidrs)) {
		cidrs.forEach((cidr) => companyCidrCache.set(cidr, company));
	}
};

/**
 * @description - Extract IP address from read stream line
 * @param {string} line - A line from the read stream created from the .txt file
 * @returns {string[] | undefined} - an array of IP addresses
 */
exports.extractIpAddressesFromSplunkData =
	function extractIpAddressesFromSplunkData(line) {
		const errorMessage =
			'extractIpAddressesFromSplunkData function received invalid splunk data input';

		const { result } = JSON.parse(line);

		if (!result || !result._raw) {
			console.error(errorMessage);
			return [];
		}

		const { _raw } = result;
		const rawSplunkIpAddresses = _raw.match(/fwd="([^"]*)"/);

		if (!rawSplunkIpAddresses) {
			console.error(errorMessage);
			return [];
		}

		const foundIps = rawSplunkIpAddresses[1].match(
			/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g
		);

		return foundIps ? foundIps : null;
	};

/**
 * @description - Check if an IP matches any company CIDRs in the cache
 * @param {string} ipAddress - An IP address
 * @param {Map<string, string>} companyCidrCache - A cache of company CIDRs
 * @returns {Promise<(string | undefined)>} - The company found in the CIDR cache
 */
async function checkIpAgainstCidrCache(ipAddress, companyCidrCache) {
	try {
		const addr = ipaddr.parse(ipAddress);

		for (const [cidr, company] of companyCidrCache.entries()) {
			if (addr.match(ipaddr.parseCIDR(cidr))) {
				return company;
			}
		}
	} catch (/** @type {any} */ error) {
		console.warn(`ipaddr API unable to process IP "${ipAddress}": ${error}`);
	}
}

/**
 * @description - Perform WHOIS lookup with caching
 * @param {string} ipAddress - An IP address to execute WHOIS lookup
 * @param {Map<string, string>} companyCidrCache - A cache of company CIDRs
 * @param {Map<string, string>} whoisIpCompanyCache - A cache of company's IP addresses from WHOIS lookup
 * @returns {Promise<string>} - The company the IP address belongs to
 */
async function getCompanyForIp(
	ipAddress,
	companyCidrCache,
	whoisIpCompanyCache
) {
	// check both the CIDR cache and WHOIS cache first
	const cachedCompany = await checkIpAgainstCidrCache(
		ipAddress,
		companyCidrCache
	);
	if (cachedCompany) {
		return cachedCompany;
	}

	if (whoisIpCompanyCache.has(ipAddress)) {
		return whoisIpCompanyCache.get(ipAddress) || 'Unknown';
	}

	// if not in the cache then perform WHOIS lookup and update both CIDR cache and WHOIS cache
	try {
		const { stdout } = await execAsync(`whois ${ipAddress}`, { timeout: 5000 });
		const orgMatch = stdout.match(/OrgName:\s+(.*)/);
		const companyName = orgMatch ? orgMatch[1] : 'Unknown';

		const cidrMatch = stdout.match(/CIDR:\s+([^\s]+)/g);
		if (cidrMatch) {
			cidrMatch.forEach((match) => {
				const cidr = match.match(
					/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\/(?:[0-2]?[0-9]|3[0-2])\b/g
				);
				if (cidr) {
					companyCidrCache.set(cidr[0], companyName);
				}
			});
		}

		whoisIpCompanyCache.set(ipAddress, companyName);

		return companyName;
	} catch (/** @type {any} */ error) {
		console.warn(`WHOIS lookup failed for ${ipAddress}: ${error.message}`);
		whoisIpCompanyCache.set(ipAddress, 'Unknown');
		return 'Unknown';
	}
};

/**
 * @description - A function that delays requests (rate limit) by setting a timeout
 * @param {number} ms - Milliseconds to set the timeout too
 * @returns {Promise<void>}
 */
async function requestDelay(ms) {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * @description - Process WHOIS lookups in batches with rate limiting
 * @param {Map<string, Number>} ipAddressMap - A map of IP addresses and their counts
 * @param {Number} batchSize - Size of the batch
 * @param {Map<string, string>} companyCidrCache - A cache of company CIDRs
 * @param {Map<string, string>} whoisIpCompanyCache - A cache of company's IP addresses from WHOIS lookup
 * @returns {Promise<Map<string, Number>>} - A map of companies and their counts
 */
exports.processCompanyLookup = async function processCompanyLookup(
	ipAddressMap,
	batchSize,
	companyCidrCache,
	whoisIpCompanyCache
) {
	const ipAddressEntries = Array.from(ipAddressMap.entries());
	const result = new Map();
	const totalUniqueIpAddresses = ipAddressEntries.length;
	let processedIpAddresses = 0;

	console.log(`📊 Processing ${totalUniqueIpAddresses} unique IP addresses...`);

	// Process IP Address lookup in batches to improve performance
	for (let i = 0; i < ipAddressEntries.length; i += batchSize) {
		// Add a small rate limit so as not to overwhelm the WHOIS servers
		await requestDelay(200);

		const batch = ipAddressEntries.slice(i, i + batchSize);
		const batchPromises = batch.map(async ([ipAddress, ipCount]) => {
			const company = await getCompanyForIp(
				ipAddress,
				companyCidrCache,
				whoisIpCompanyCache
			);

			// Normalise company names
			let normalisedCompany = company;
			if (company.includes('Amazon')) {
				normalisedCompany = 'Amazon';
			}
			if (company.includes('Fastly')) {
				normalisedCompany = 'Fastly';
			}

			return {
				ipCount,
				normalisedCompany
			};
		});

		const batchResults = await Promise.all(batchPromises);

		batchResults.forEach(({ ipCount, normalisedCompany }) => {
			result.set(
				normalisedCompany,
				(result.get(normalisedCompany) || 0) + ipCount
			);
			processedIpAddresses++;
		});

		// Log progress
		const percentComplete = (
			(processedIpAddresses / totalUniqueIpAddresses) *
			100
		).toFixed(1);

		console.log(
			`📝 Progress: ${processedIpAddresses}/${totalUniqueIpAddresses} IPs (${percentComplete}%)`
		);
	}

	return result;
};