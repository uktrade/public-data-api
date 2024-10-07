import events from 'eventslibjs'

/**
 * @param {HTMLElement} $module - Module
 */
export default function ($module) {
  this.init = () => {
    if (!$module) {
      return
    }

    const nodes = $module.querySelectorAll('a[href="#"]')
    nodes.forEach((node) => {
      events.on('click', node, alertUser)
    })

    /**
     * @param {Event} event - Event
     */
    function alertUser(event) {
      event.preventDefault()
      const message =
        event.target.dataset.message || 'Sorry, this hasn’t been built yet'

      window.alert(message)
    }
  }
}
