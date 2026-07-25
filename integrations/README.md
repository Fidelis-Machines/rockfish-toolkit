# Integrations — response pipelines & output recipes

> **Status: coming soon.** Reference integrations for routing Rockfish NDR
> detections into your response and automation stack. Rockfish already
> **publishes** to MQTT, Kafka, and webhooks at the appropriate license tiers —
> the recipes here sit on top of those outputs and show how to wire them into
> downstream systems.

Each subdirectory is one integration function:

| Directory | Integration | Rockfish output | Status |
|---|---|---|---|
| [`mqtt/`](mqtt/) | MQTT → OT/SCADA broker | MQTT (Enterprise) | planned |
| [`kafka/`](kafka/) | Kafka topic bridge → SIEM / data lake | Kafka (Enterprise) | planned |
| [`webhook/`](webhook/) | Webhook → SOAR / ticketing / chat | Webhook (Professional) | planned |

## Contributing an integration

Want a specific integration prioritized, or have one to share?
[Open an issue](https://github.com/Fidelis-Machines/rockfish-toolkit/issues).
