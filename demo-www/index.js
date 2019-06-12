import { ZcashClient } from 'zcash-client-sdk'

const address = document.getElementById('zcash-client-address')
const balance = document.getElementById('zcash-client-balance')
const yesBalance = document.getElementById('zcash-client-yes-balance')
const noBalance = document.getElementById('zcash-client-no-balance')
const sendToAddress = document.getElementById('zcash-client-send-to-address')
const sendValue = document.getElementById('zcash-client-send-value')
const sendAction = document.getElementById('zcash-client-send-action')
const syncStatus = document.getElementById('zcash-client-sync-status')

var zcashClient = new ZcashClient('http://localhost:8081', {
  setAddress: (newAddress) => {
    address.textContent = newAddress
  },
  updateBalance: (newBalance) => {
    balance.textContent = `Balance: ${newBalance} TAZ`
    if (newBalance > 0) {
      yesBalance.style.display = ''
      noBalance.style.display = 'none'
    } else {
      yesBalance.style.display = 'none'
      noBalance.style.display = ''
    }
  },
  updateSyncStatus: (syncedHeight, latestHeight) => {
    if (syncedHeight === latestHeight) {
      syncStatus.textContent = `Synced! Latest height: ${latestHeight}`
    } else {
      syncStatus.textContent = `Syncing (${syncedHeight} / ${latestHeight})...`
    }
  }
}, {
  height: 500000,
  hash: '004fada8d4dbc5e80b13522d2c6bd0116113c9b7197f0c6be69bc7a62f2824cd',
  sapling_tree: '01b733e839b5f844287a6a491409a991ec70277f39a50c99163ed378d23a829a0700100001916db36dfb9a0cf26115ed050b264546c0fa23459433c31fd72f63d188202f2400011f5f4e3bd18da479f48d674dbab64454f6995b113fa21c9d8853a9e764fb3e1f01df9d2c233ca60360e3c2bb73caf5839a1be634c8b99aea22d02abda2e747d9100001970d41722c078288101acd0a75612acfb4c434f2a55aab09fb4e812accc2ba7301485150f0deac7774dcd0fe32043bde9ba2b6bbfff787ad074339af68e88ee70101601324f1421e00a43ef57f197faf385ee4cac65aab58048016ecbd94e022973701e1b17f4bd9d1b6ca1107f619ac6d27b53dd3350d5be09b08935923cbed97906c0000000000011f8322ef806eb2430dc4a7a41c1b344bea5be946efc7b4349c1c9edb14ff9d39'
})

zcashClient.load(() => {
  // Register event handlers
  sendAction.onclick = () => {
    sendAction.disabled = true
    sendAction.textContent = 'Sending...'

    var to = sendToAddress.value
    var value = sendValue.value

    zcashClient.sendToAddress(to, value, () => {
      sendAction.disabled = false
      sendAction.textContent = 'Send!'
    })
  }

  // Loading complete, show the wallet
  document.getElementById('zcash-client-loading').remove()
  document.getElementById('zcash-client-content').style.display = ''

  zcashClient.sync()
})
