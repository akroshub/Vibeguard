const { run, main } = require('./src/cli');

module.exports = { run, main };

if (require.main === module) {
    main(process.argv.slice(2));
}
