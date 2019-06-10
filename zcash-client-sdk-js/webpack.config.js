var path = require('path')

module.exports = {
  entry: './src/index.js',
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: 'zcash-client-sdk.js',
    library: 'zcashClientSdk'
  }
}
