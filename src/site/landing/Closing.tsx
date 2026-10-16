import { closing } from './copy'
import { RunActions } from './RunActions'

/** The closing band: the invitation again, beside the door (above it on a phone). */
export const Closing = () => (
  <section className="closing" id="start" aria-labelledby="start-title">
    <div className="closing-copy">
      <h2 id="start-title">{closing.title}</h2>
      <p className="feature-body">{closing.body}</p>
      <RunActions />
      <p className="licence-line">{closing.licence}</p>
    </div>
    <img className="closing-door" src="/brand/door.webp" alt="" width="620" height="910" />
  </section>
)
