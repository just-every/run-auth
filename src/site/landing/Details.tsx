import { details } from './copy'
import { Icon } from './icons'

/** Also included: six tiles, three by two at 1440 and two columns on a phone. */
export const Details = () => (
  <section className="details" id="details" aria-labelledby="details-title">
    <p className="eyebrow">{details.eyebrow}</p>
    <h2 id="details-title">{details.title}</h2>
    <ul className="tiles">
      {details.tiles.map(tile => (
        <li className="tile" key={tile.label}><span className="draw-avatar"><Icon name={tile.icon} /></span><div><strong>{tile.label}</strong><p>{tile.line}</p></div></li>
      ))}
    </ul>
  </section>
)
