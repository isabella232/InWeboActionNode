<!--
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2020 ForgeRock AS.
-->

# InWeboActionNode
Authentication node for ForgeRock's [Identity Platform][forgerock_platform] 6.5.0.1 and above. 
This node is used to integrate with [InWebo Strong authentication](https://www.inwebo.com/) 
solution.
It can be used in 4 different ways: 
1. *PUSH*: this mode triggers a push authentication on the inWebo mobile app, 
2. *CHECK* : use this mode to request inWebo if the end-user has done the push action on her mobile
phone, 
3. *OTP*: this mode retrieves an OTP from the `sharedstate` and validates it with InWebo, 
4. *VA*: Display inWebo's Virtual authenticator to the end-user for authentication.

The Figure below shows an example of an authentication tree that is using this node with different
modes: 
 
![inWeboExampleTree](./inWeboExampleTree.png)

## Deploy
Copy the `.jar` file from the `../target` directory into the 
`../web-container/webapps/openam/WEB-INF/lib` directory where AM is deployed.
Restart the web container to pick up the new node.
The node will then appear in the authentication trees designer.

**Specific deployment instructions**

- inWebo dependencies - TODO
- The code in this repository has binary dependencies that live in the ForgeRock maven repository.
Maven can be configured to authenticate to this repository by following the following 
[ForgeRock Knowledge Base Article](https://backstage.forgerock.com/knowledge/kb/article/a74096897).

## Usage
This node can be used in 4 different mode explained below.
### *PUSH* mode
TODO
### *CHECK* mode
TODO
### *OTP* mode
TODO
### *VA* mode
[inWebo Virtual Authenticator documentation](https://inwebo.atlassian.net/wiki/spaces/DOCS/pages/1687770/Quickstart+inWebo+Virtual+Authenticator)
TODO

[forgerock_platform](https://www.forgerock.com/platform/)
TODO 

![Helium documentation](https://api.media.atlassian.com/file/16b58e75-7fec-4294-9213-de7f1f2d84f6/binary?token=eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJjMGM0NjlhNC1hMDcyLTQyZTYtYmMwNi04MzNhOTcwYjE2OWEiLCJhY2Nlc3MiOnsidXJuOmZpbGVzdG9yZTpmaWxlOjE2YjU4ZTc1LTdmZWMtNDI5NC05MjEzLWRlN2YxZjJkODRmNiI6WyJyZWFkIl19LCJleHAiOjE1OTI0MDI3MjYsIm5iZiI6MTU5MjMxOTc0Nn0.Lqp-cDbIgh4WLjPQU4-1-xaaGCgHJhlVxN8ZKdipxqk&client=c0c469a4-a072-42e6-bc06-833a970b169a&name=Mode2HE.png&max-age=2940&width=604&height=400)