import { ZcashClient } from 'zcash-client-sdk'

const address = document.getElementById('zcash-client-address')
const balance = document.getElementById('zcash-client-balance')
const noBalance = document.getElementById('zcash-client-no-balance')

var zcashClient = new ZcashClient({
  setAddress: (newAddress) => {
    address.textContent = newAddress
  },
  updateBalance: (newBalance) => {
    balance.textContent = `Balance: ${newBalance} TAZ`
    if (newBalance > 0) {
      noBalance.style.display = 'none'
    } else {
      noBalance.style.display = ''
    }
  }
})

zcashClient.load(() => {
  // Loading complete, show the wallet
  document.getElementById('zcash-client-loading').remove()
  document.getElementById('zcash-client-content').style.display = ''
})
