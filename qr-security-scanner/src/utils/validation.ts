export const isURL = (text: string): boolean => {
  try {
    const urlPattern = /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w-./?%&=]*)?$/i;
    return urlPattern.test(text) || text.startsWith('http://') || text.startsWith('https://');
  } catch {
    return false;
  }
};