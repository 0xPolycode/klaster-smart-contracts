export function getUnixTimestamp(offsetInSeconds: number = 0): string {
  const now = Math.floor(Date.now() / 1000);
  return (now + offsetInSeconds).toString();
}
