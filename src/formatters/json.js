/**
 * gitambush JSON Formatter
 */

export function formatJson(scanResult) {
  return JSON.stringify(scanResult, null, 2);
}
