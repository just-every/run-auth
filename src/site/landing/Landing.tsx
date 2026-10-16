import { SiteFrame } from '../shell/SiteFrame'
import { Closing } from './Closing'
import { features } from './copy'
import { Details } from './Details'
import { Feature } from './Feature'
import { Hero } from './Hero'
import './landing.css'

/** The run site's homepage, in the approved order: hero, six sections, the details, the closing band. */
export const Landing = () => (
  <SiteFrame className="landing">
    <Hero />
    {features.map(feature => <Feature key={feature.id} feature={feature} />)}
    <Details />
    <Closing />
  </SiteFrame>
)
