class Logger {
  static log(message) {
    console.log(`[LOG] ${new Date().toISOString()}: ${message}`);
  }

  static info(message) {
    console.info(`[INFO] ${new Date().toISOString()}: ${message}`);
  }

  static warn(message) {
    console.warn(`[WARN] ${new Date().toISOString()}: ${message}`);
  }

  static error(message) {
    console.error(`[ERROR] ${new Date().toISOString()}: ${message}`);
  }

  static debug(message) {
    if (process.env.NODE_ENV === 'development') {
      console.debug(`[DEBUG] ${new Date().toISOString()}: ${message}`);
    }
  }
}

module.exports = Logger;