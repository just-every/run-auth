// Code examples retain their own horizontal keyboard navigation, including
// when a focused region was brought into view from elsewhere in the guide.
document.addEventListener('keydown', event => {
  if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return
  if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return
  const code = event.target instanceof Element ? event.target.closest('.docs-prose pre.docs-code') : null
  if (!code || code.scrollWidth <= code.clientWidth) return
  event.preventDefault()
  code.scrollLeft += event.key === 'ArrowRight' ? 40 : -40
})
