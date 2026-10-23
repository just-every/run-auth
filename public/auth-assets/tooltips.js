(() => {
  const tip = document.createElement('span')
  tip.className = 'auth-tooltip'; tip.id = 'auth-tooltip'; tip.role = 'tooltip'; tip.hidden = true
  document.body.append(tip)
  let anchor, timer
  const dismiss = () => {
    clearTimeout(timer); tip.hidden = true
    anchor?.removeAttribute('aria-describedby'); anchor = null
  }
  const position = () => {
    if (!anchor || tip.hidden) return
    const box = anchor.getBoundingClientRect(), bounds = tip.getBoundingClientRect()
    tip.style.left = `${Math.max(8, Math.min(innerWidth - bounds.width - 8, box.left + box.width / 2 - bounds.width / 2))}px`
    tip.style.top = `${Math.max(8, Math.min(innerHeight - bounds.height - 8, box.bottom + 8))}px`
  }
  const show = control => {
    dismiss(); anchor = control; tip.textContent = control.dataset.tooltip; tip.hidden = false
    control.setAttribute('aria-describedby', tip.id); position()
  }
  for (const control of document.querySelectorAll('[data-tooltip]')) {
    control.addEventListener('mouseenter', () => {
      if (document.activeElement === control) { show(control); return }
      dismiss(); timer = setTimeout(() => show(control), 300)
    })
    control.addEventListener('mouseleave', () => { if (document.activeElement !== control) dismiss() })
    control.addEventListener('focus', () => show(control))
    control.addEventListener('blur', () => { if (!control.matches(':hover')) dismiss() })
  }
  document.addEventListener('keydown', event => { if (event.key === 'Escape') dismiss() })
  // Scrolling a control into view must not cancel its pending hover or focus.
  document.addEventListener('scroll', position, true)
  window.addEventListener('resize', position)
})()
