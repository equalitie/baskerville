### Server side for plugin integration

##### Handles:
- the wordpress portion (wpsec-waf-plugin) is the part that actually tee's off the requests, gathering the metadata needed and sending that metadata to the server for ML processing
- receiving tee'd requests
- verifying payments
- authn
- authz
- processing requests into prediction pipeline
- consuming predictions from pipeline
- filtering predictions to determine if they're relevant to the wordpress integration
- pushing any rules ML pipeline generates back to customer to enforce
- hosts solver for challenges

