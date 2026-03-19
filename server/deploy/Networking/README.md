## How does the networking work?


# db-gateway-process flow comprises a couple different possibilities that include receiving & sending BOTH internal AND external communications:

- when the from-kafka-process has new aggregation data or a new prediction, it will contact db gateway internally
    - from-kafka-process -> db-gateway-process 

- when the user makes a change to their configurations, this is intercept by the worker and forwarded on to the db gateway:
    - user interaction with app -> cloudflare worker -> db-gateway-process
  
- when the db gateway responds to a users request, it will need to be able to send back to the worker
    - db-gateway-process -> cloudflare worker




# service.yaml

- A service is always going to front a pod

- It is really important to understand the distinction between the "port" and "targetPort"
    
    - When a pod want to talk to another pod, it goes THROUGH the service (at least trivially) as it needs to lookup where to go via internal dns system
    
    - The "targetPort" is the port that the process in question (ie  your actual process running in the pod) is actively listening on for traffic
    - The "port" in the Service is what OTHER pods (or nginx) will use to talk to to-kafka-process.
        - The Service acts as a middleman, receiving traffic on its port and forwarding it to the pod's targetPort.

    - The "port" and the "targetPort" need not match and often they don’t, especially when you standardize the port for ease of use across multiple services (e.g., exposing port: 80 for all services).

    - When another process wants to talk to the to-kafka-process, it will send its request to the to-kafka-process THROUGH the service that fronts the to-kafka-process VIA the "port" and the request is the FORWARDED on to the to-kafka-process VIA the "targetPort". 

    - **The reason this is important**:
        - The Service provides an abstraction layer over pods. It exposes a stable port (e.g., port: 80) that other processes or ingress controllers (like nginx) can use, while the actual processes can listen on different ports internally (via targetPort). This is because kubernetes pods can crash or go on vacation so when they get replaced, we need to make sure that we can still reach the pod currently assigned to do the work.
        
    apiVersion: v1
    kind: Service
    metadata:
        name: to-kafka-process-service
        namespace: baskerville_server_production
    spec:
        selector:
            app: to-kafka-process #selects the name we gave the process at the level of the deployment definition
    ports:
        - protocol: TCP
            port: 8085
            targetPort: 8085
    type: ClusterIP


**Example:**

    - Let’s say Process A wants to communicate with to-kafka-process.
        1) Process A sends a request to http://to-kafka-process-service:80/endpoint.
            - 80 is the port defined in the Service.
            - Kubernetes DNS resolves to-kafka-process-service to the IP address of the Service.

        2) Service (to-kafka-process-service) receives the request on port 80 and forwards it to one of the pods backing to-kafka-process.
            - The Service uses targetPort: 8085 to forward the request to the pod where to-kafka-process is running.
        
        3) to-kafka-process receives the request on targetPort 8085 and processes it.



**What is ClusterIP and why use it here?**
- A ClusterIP service exposes the service INTERNALLY WITHIN the cluster. 
- It provides a stable, internal IP address that other pods within the cluster can use to communicate with the service.
    - It is ONLY useful in the context of INTERNAL (within the cluster) communications.
        - For example when our service does not need to be accessed externally (e.g., by users or external systems) but is meant to be used by other services within the cluster.

    - This is as opposed to those processes that are EXTERNALLY facing and would require Ingress
    
    - This is why we use an Ingress rule at the level of nginx. It is EXTERNALLY facing. Requests come from the internet directly to it.
        - Requests cannot come from the internet directly to the to-kafka-process. 
        - Instad, we rely on the Ingress at the level of nginx to receive, then after terminating TLS, forward on to the appropriate process
            - In order to be able to forward the request to the appropriate process, we expose a Service fronting our process which specifies what port to reach out to it on

    - Since our to-kafka-process only talks to other services in the cluster, and nginx (via ingress) handles traffic from outside the cluster; we use ClusterIP as to-kafka-process isnot exposing its service directly to the external users.


**What is a NodePort and why not use it here?**
- A NodePort service exposes your service on a specific port on each node in your cluster. This allows external traffic to access the service by hitting the IP of any node in the cluster.
- You would use a NodePort if you want a simple, direct way to expose your service externally without using an Ingress or LoadBalancer.
- Since we are using our to-kafka-process behind a reverse proxy, it would not make sense to receive traffic directly to the process.

**What is a LoadBalancer and why not use it here?** note: this is not *that* type of loadbalancer, it is instead a kubernetes construct named by a sadist.
- A LoadBalancer service creates an external load balancer that distributes traffic across your service pods.
- You would use this approach if you want to expose your service to the internet with load balancing.
- A LoadBalancer service in Kubernetes provisions a cloud provider-specific load balancer that can expose your service directly to the internet.
    -  Instead of using an Ingress as a gateway, each LoadBalancer service gets its own public IP. This allows external users to access the service directly without going through a centralized ingress point.
    - It automatically distributes traffic across the pods in the service. This is useful in cloud environments where the load balancer integrates with the cloud provider's infrastructure (e.g., AWS ELB, GCP Load Balancer).
        - In other words, with LoadBalancer, each service that you expose gets its own external endpoint, unlike Ingress, where multiple services can share one endpoint and be routed based on paths or domains.

    - This is inherently different from what we need: our to-kafka-process is meant to receive traffic from the outside world, but is much more interested in internal/cluster communications.
    - Using the ClusterIP + Ingress more closely aligns with our needs:
        - ClusterIP services provide internal access to other services in the cluster. They are not directly accessible from outside the cluster.
        - Ingress acts as a gateway or router for external traffic, forwarding requests to the appropriate internal services.
        - The Ingress Controller (such as NGINX) itself acts as a load balancer by distributing traffic across services/pods.
            - In particular, Ingress allows for host-based and path-based routing, meaning you can manage multiple services (such as your to-kafka-process and others) behind a single IP, but still direct traffic based on domain names or URL paths.
                - **This is exactly what we need as the Ingress is backed by a ClusterIP service, which handles traffic forwarding within the cluster.**
                    - **a LoadBalancer service in Kubernetes does NOT inherently support domain name or path-based routing like an Ingress does.**
                - In this setup, Ingress does most of the heavy lifting when it comes to routing and load balancing across your services. The external traffic is directed to the Ingress controller, which then forwards it to the appropriate internal service (via ClusterIP) based on the rules you define.


# ingress.yaml

apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: to-kafka-process-ingress
  namespace: baskerville_server_production
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /$2
    cert-manager.io/issuer: "letsencrypt-prod"  #Let's Encrypt HTTPS
    nginx.ingress.kubernetes.io/use-regex: "true"
    nginx.ingress.kubernetes.io/configuration-snippet: |
      proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_set_header X-Forwarded-Host $host;
      proxy_set_header X-Forwarded-Port $server_port;
spec:
  ingressClassName: nginx
  tls:  #enable HTTPS
  - hosts:
    - greything.com
    secretName: to-kafka-TLS-secret #the secretName that was created for us by cert-manager in the certificate resource definition. This gives us access to the TLS info required for encrypted communication to this process in particular
  rules:
  - host: greything.com
    http:
      paths:
      - path: /prediction_pipeline(/|$)(.*)
        pathType: Prefix
        backend:
          service:
            name: to-kafka-process-service  #the Service resource fronting the to-kafka-process
            port:
              number: 8085 #the port to-kafka-process is listening on


- the reason we rewrite-target: /$2 and assign the paths: path key as /prediction_pipeline(/|$)(.*) is that when a request is made to https://greything.com/prediction_pipeline, it will be rewritten to /, essentially stripping the /prediction_pipeline prefix before forwarding the request to our to-kafka-process-service. 

- The (/|$)(.*) part captures everything after "/prediction_pipeline" and forwards it as captured by $2 (since $1 would be either "/" or the end of the line, and $2 is everything after /prediction_pipeline). 

- This is important because our Worker expects specific endpoints that do not contain "/prediction_pipeline/endpoint" but rather just /endpoint

- therefore the current ingress rule specifies that any request to greything.com/prediction_pipeline (and paths under it) should be forwarded to the to-kafka-process-service on port 8085.

- we include nginx.ingress.kubernetes.io/use-regex: "true" annotation to the Ingress to enabled regular expression support (a feature of the NGINX Ingress Controller)
- This is important because we want to be able to keep anything that comes AFTER the /prediction_pipeline since that is needed for the server. 
    - For example a request to: https://greything.com/prediction_pipeline/log should effectively be sending a request to our server at the /log endpoint


- The key to understanding how this works is in the combination of:
  ## 1) use-regex: "true" 
  ## 2) the path definition /prediction_pipeline(/|$)(.*). 
  ## 3) the rewrite-target: /$2 annotation 
  
## WRT 1)
  #use-regex: "true": This tells NGINX to treat the paths as regular expressions, allowing for pattern matching and capturing groups.

## WRT 2)
   - Path /prediction_pipeline(/|$)(.*): This regular expression matches requests that start with /prediction_pipeline. 
   - It has two capturing groups:

    - The first group: (/|$) 
        captures either a slash "/" or the end of the string "$". This is used to ensure that BOTH "/prediction_pipeline" and "/prediction_pipeline/" are matched.

    - The second group: (.*) 
       - captures everything AFTER "/prediction_pipeline" or "/prediction_pipeline/"". This includes any additional path segments OR an empty string if there are none.

## WRT 3)
- rewrite-target: /$2: Uses the captured group from the path to REWRITE the request's path BEFORE it's FORWARDED to the to-kafka-process.
  - "$2" refers to the SECOND capturing group in the path regular expression, which is everything AFTER "/prediction_pipeline" or "/prediction_pipeline/"". 
    - By rewriting the target to /$2, you're effectively stripping the /prediction_pipeline prefix from the path.

- This setup allows our Ingress to dynamically rewrite incoming paths, ensuring that a request to, for example: "/prediction_pipeline/arbitrary_endpoint" is transformed into "/arbitrary_endpoint" by the time it reaches the to-kafka-process.