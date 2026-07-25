# Kafka integration — *coming soon*

Recipe for streaming Rockfish NDR detections to a Kafka topic for SIEM and
data-lake ingestion.

Rockfish NDR publishes to Kafka natively at the **Enterprise** tier. This
directory will hold a ready-to-adapt reference:

- broker / topic / partition configuration
- detection → Kafka record schema (key strategy, serialization)
- a worked consumer example (SIEM / data lake)

**Status:** planned. Track or request it via
[issues](https://github.com/Fidelis-Machines/rockfish-toolkit/issues).
