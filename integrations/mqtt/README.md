# MQTT integration — *coming soon*

Recipe for routing Rockfish NDR detections to an MQTT broker (e.g. a plant /
SCADA broker) so dispositions and pre-intrusion alerts can drive HMI and
operator workflows.

Rockfish NDR publishes to MQTT natively at the **Enterprise** tier. This
directory will hold a ready-to-adapt reference:

- broker connection & topic-mapping configuration
- detection → MQTT payload schema (QoS, retain, topic-per-severity)
- a worked end-to-end example

**Status:** planned. Track or request it via
[issues](https://github.com/Fidelis-Machines/rockfish-toolkit/issues).
