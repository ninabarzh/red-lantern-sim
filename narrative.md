# Simulation narrative

The thing about a city that runs on light, logic, and the quiet hum of routers was that it had a peculiar sense of 
humour. The Scarlet Semaphore, you see, was never meant to be a threat. In a dusty attic above a curry house that did 
suspiciously good chips, they were a hackerspace, a guild of tinkerers. 

[![Scarlet Semaphore](https://github.com/ninabarzh/red-lantern-detection/blob/main/assets/scarlet-semaphore.png)](https://red.tymyrddin.dev/docs/scarlet/)

[Their charter](https://red.tymyrddin.dev/docs/scarlet/charter) was one of curiosity, not conquest. They poked at 
systems to see how they squeaked, a digital version of kicking tyres. Their latest project was 
[Operation Red Lantern](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/), targeting the Guild Registry, a 
dusty, important, and frankly rather pompous piece of civic plumbing that controlled professional certifications. 
It was, in their view, [begging for a gentle nudge](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/rose/gambit).

[![Operation Red Lantern or False Horizons](https://github.com/ninabarzh/red-lantern-detection/blob/main/assets/red-lanterns.png)](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/rose/patrician-red-line)

The nudge, however, had 
[unforeseen consequences](https://github.com/ninabarzh/red-lantern-sim/blob/main/examples/playbook3-practice.json). 
It was like adjusting a single, obscure valve in a steamworks only 
to find, three streets over, that all the red lanterns (the city’s critical signal lights for routing emergency data) 
had begun to blink in a frantic, anarchic samba. The Semaphore had, entirely by accident, performed a rather elegant 
'control-plane attack'. They hadn't stolen a single byte, but they had convinced the city's nervous system that a 
perfectly normal street was, in fact, a canal.

This got you noticed. Specifically, it got you noticed by the Department of Silent Stability, whose job it was to 
[ensure the city's digital hum never became a screech](https://blue.tymyrddin.dev/docs/shadows/about), among 
[other things](https://blue.tymyrddin.dev/docs/shadows/red-lantern/kickoff/internal-notice-tss).

[![Dept. of Silent Stability](https://github.com/ninabarzh/red-lantern-detection/blob/main/assets/silent-stability.png)](https://blue.tymyrddin.dev/docs/shadows/)

Their analysts, people who could read packet loss like tea leaves, drafted a deeply concerned 
[internal briefing](https://blue.tymyrddin.dev/docs/shadows/red-lantern/kickoff/internal-briefing-doss). It was a 
masterpiece of understated alarm, outlining the "anomalous re-routing events" and their potential to cause 
"localised consensus confusion". It was also, in a stroke of cosmic irony, immediately intercepted by the Semaphore 
themselves, who read it with a mixture of horror and professional pride. "Oh," said their de facto leader, a network 
archaeologist named Ponder. "We've gone and done a proper thing, haven't we?"

[![The Patrician](https://github.com/ninabarzh/red-lantern-detection/blob/main/assets/patrician.png)](https://indigo.tymyrddin.dev/docs/vetinari/)

The matter landed, as all truly delicate matters did, 
[on the desk of the Patrician](https://blue.tymyrddin.dev/docs/shadows/red-lantern/kickoff/to-his-eminence). 
The Patrician did not do panic. He did balance. The city was a complex, self-regulating organism, and his role was 
that of a gardener, pruning threats and encouraging useful growth. He saw the Scarlet Semaphore not as weeds to be 
pulled, but as a particularly vigorous, if misplaced, new species of rose. Shutting them down would waste talent. 
Leaving them be was an invitation to accidental catastrophe.

His solution was a stroke of lateral thinking. 
[He summoned Ponder](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/wall/ponders-visit). "Your curiosity," 
the Patrician stated, sipping a delicate brandy, "has value. Your current method of satisfying it, however, involves 
making the traffic lights dance. This is disruptive. I propose a change of venue."

[![Purple Lantern Practice Ltd](https://github.com/ninabarzh/red-lantern-detection/blob/main/assets/purple-lantern.png)](https://purple.tymyrddin.dev/docs/lantern/)

And so, Purple Lantern Practice Ltd. was born. 
[Its mandate was a delicious paradox](https://purple.tymyrddin.dev/docs/lantern/red-lanterns/spark/patrician-engagement): 
to professionally simulate disasters so they would never actually happen. Ponder was tasked with building the 
[red-lantern-sim](https://github.com/ninabarzh/red-lantern-sim), a theatre of digital warfare where attacks could be 
staged without a single real packet going astray. His first recruits were his baffled, slightly chastened friends 
from the Scarlet Semaphore. "Stop hacking the city," he told them. "Start documenting *how* we hacked it. 
Turn our clever accident into a [scenario for the simulator](https://github.com/ninabarzh/red-lantern-sim/tree/main/simulator/scenarios)."

Meanwhile, back in the mirrored halls of the Department of Silent Stability, the mood shifted. The intercepted 
briefing was no longer a security failure; it was a requirements document. Their new mission, fed by the simulator's 
outputs, was to [build the detection logic](https://blue.tymyrddin.dev/docs/shadows/red-lantern/detection/) that would 
have caught the Semaphore's prank *before* the lanterns started their samba. They began crafting [elegant correlation 
rules](https://blue.tymyrddin.dev/docs/shadows/red-lantern/correlation/), learning to distinguish the signature of a mischievous "control-plane" tweak from the common noise of a faulty cable.

The project became a grand, recursive loop: a controlled burn to fireproof the city. The Semaphore, now on the payroll, 
would devise a new, ever-more cunning attack scenario in the simulator. The *red-lantern-sim* would spit out its 
telemetry: cryptic `BMP ROUTE:` announcements, urgent syslog mutterings from `edge-router-01`, and the ghostly tracery 
of falsified ROA certificates from phantom registries. This data stream would flow to the analysts at the Department, 
who would pour over it, writing the detection spells: 
[the Wazuh decoders and correlation alerts](https://github.com/ninabarzh/red-lantern-detection), to spot the attack's 
faint shimmer in the real network traffic.

It was security through immersive, sanctioned paranoia. The Patrician had converted a threat into a vaccine. The 
Scarlet Semaphore got to be [brilliantly disruptive](https://red.tymyrddin.dev/docs/scarlet/op-red-lantern/bench/) 
without causing a real mess. The Department of Silent Stability got a perpetual, intelligent training partner that 
didn't require filing incident reports. And the city’s data flows continued to hum, their pathways growing more 
resilient with every simulated catastrophe. The red lanterns now glowed with a steady, untroubled light, their brief, 
chaotic dance preserved only in the scenario files of a simulator and the detection rules of a watchful blue team, 
a permanent testament to the day curiosity almost broke the city, and was instead put splendidly to work.