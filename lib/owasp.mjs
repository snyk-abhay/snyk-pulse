// OWASP Top 10:2021 categories and their officially mapped CWEs
// (https://owasp.org/Top10/, "List of Mapped CWEs" in each category).
export const OWASP_TOP10 = {
  "A01:2021 Broken Access Control": [22,23,35,59,200,201,219,264,275,276,284,285,352,359,377,402,425,441,497,538,540,548,552,566,601,639,651,668,706,862,863,913,922,1275],
  "A02:2021 Cryptographic Failures": [261,296,310,319,321,322,323,324,325,326,327,328,329,330,331,335,336,337,338,340,347,523,720,757,759,760,780,818,916],
  "A03:2021 Injection": [20,74,75,77,78,79,80,83,87,88,89,90,91,93,94,95,96,97,98,99,100,113,116,138,184,470,471,564,610,643,644,652,917],
  "A04:2021 Insecure Design": [73,183,209,213,235,256,257,266,269,280,311,312,313,316,419,430,434,444,451,472,501,522,525,539,579,598,602,642,646,650,653,656,657,799,807,840,841,927,1021,1173],
  "A05:2021 Security Misconfiguration": [2,11,13,15,16,260,315,520,526,537,541,547,611,614,756,776,942,1004,1032,1174],
  "A06:2021 Vulnerable and Outdated Components": [937,1035,1104],
  "A07:2021 Identification and Authentication Failures": [255,259,287,288,290,294,295,297,300,302,304,306,307,346,384,521,613,620,640,798,940,1216],
  "A08:2021 Software and Data Integrity Failures": [345,353,426,494,502,565,784,829,830,915],
  "A09:2021 Security Logging and Monitoring Failures": [117,223,532,778],
  "A10:2021 Server-Side Request Forgery": [918],
};

const byCwe = new Map();
for (const [category, ids] of Object.entries(OWASP_TOP10))
  for (const id of ids) byCwe.set(`CWE-${id}`, category);

const COMPONENTS = "A06:2021 Vulnerable and Outdated Components";

/**
 * OWASP categories for one finding. CWEs map through the official lists, and
 * vulnerabilities in third-party packages (SCA, container images) are also A06.
 */
export function owaspCategories(issue) {
  const categories = new Set(
    (issue.cwe || "")
      .split(", ")
      .map((cwe) => byCwe.get(cwe))
      .filter(Boolean),
  );
  // Known-vulnerable dependencies (SCA / container images); license findings are not security flaws.
  if (
    /open source|container/i.test(issue.product) &&
    !/license/i.test(issue.issue_type)
  )
    categories.add(COMPONENTS);
  return categories;
}
