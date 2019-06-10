import { Client } from 'zcash-client-backend-wasm'

const COIN = 100000000

export class ZcashClient {
  constructor (uiHandlers) {
    this.client = Client.new()
    this.uiHandlers = uiHandlers
  }

  updateUI () {
    this.uiHandlers.updateBalance(this.client.balance() / COIN)
  }

  load (onFinished) {
    var self = this

    var loader = () => {
      // Register event handlers

      // Initial UI updates
      self.uiHandlers.setAddress(self.client.address())
      self.updateUI()

      // Finished loading!
      onFinished()
    }

    // document.addEventListener('DOMContentLoaded', loader, false)
    loader()
  }
}
