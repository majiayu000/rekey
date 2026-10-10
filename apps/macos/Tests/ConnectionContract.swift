import Foundation
import LocalAuthentication
import CryptoKit

@main struct ConnectionContract {
    static func main() throws {
        for name in ["anthropic","openai","glm","glm-responses","github-pat","github-git","generic-bearer","generic-header"]+OAuthSetup.presets {
            precondition(OnboardingRoute(url:URL(string:"rekey://add/"+name)!) == .add(name))
        }
        precondition(OnboardingRoute(url:URL(string:"rekey://add/anthropic?secret=synthetic")!) == nil)
        precondition(OnboardingRoute(url:URL(string:"rekey://import?path=%2Ftmp%2Fsynthetic%20project%2F.env")!) == .importEnv("/tmp/synthetic project/.env"))
        precondition(OnboardingRoute(url:URL(string:"rekey://import?path=relative")!) == nil)
        precondition(OnboardingRoute(url:URL(string:"rekey://import?path=%2Ftmp%2Fa&path=%2Ftmp%2Fb")!) == nil)
        precondition(OnboardingRoute(url:URL(string:"rekey://oauth?connection=synthetic")!) == .oauth("synthetic"))
        for url in ["rekey://oauth?connection=a&connection=b","rekey://oauth?connection=a&secret=synthetic","rekey://oauth?connection=%2Fescape"] {precondition(OnboardingRoute(url:URL(string:url)!) == nil)}
        let authentication=PresenceReadContext(),vaultID=UUID(),start=ContinuousClock.Instant.now
        var contexts:[LAContext]=[]
        for elapsed in [0,1,11] {
            _=try authentication.read(vaultID:vaultID,now:{start.advanced(by:.seconds(elapsed))}){context in contexts.append(context);return "synthetic-proof"}
        }
        precondition(contexts[0] === contexts[1] && contexts[1] !== contexts[2])
        do{_=try authentication.read(vaultID:vaultID,now:{start.advanced(by:.seconds(12))}){_ in throw UIError(message:"synthetic cancellation")}}catch{}
        _=try authentication.read(vaultID:vaultID,now:{start.advanced(by:.seconds(12))}){context in contexts.append(context);return "synthetic-proof"}
        precondition(contexts[2] !== contexts[3]);authentication.invalidate()
        let approvalID=UUID().uuidString.lowercased(),approvalUUID=UUID().uuidString.lowercased()
        var challenge:[String:Any] = ["record_type":"rekey.approval.challenge.v2","approval_request_id":approvalID,"tenant_id":approvalUUID,"principal_id":approvalUUID,"session_id":approvalUUID,"action_id":approvalUUID,"action_version":1,"resource":["type":"connection","id":"synthetic"],"schema_id":"rekey.connection-call.v1","parameter_sha256":String(repeating:"ab",count:32),"policy_version":1,"policy_sha256":String(repeating:"cd",count:32),"policy_rule_id":approvalUUID,"mode":"one-time","approver":["kind":"local-presence"],"max_uses":1,"created_at_ms":1,"max_expires_at_ms":4000000000000]
        let http:[String:Any] = ["record_type":"rekey.approval.local-review.v1","challenge":challenge,"action_name":"synthetic","origin":"https://example.com","method":"POST","canonical_request":["path":"/items","body":"synthetic"]]
        let httpReview=try LocalApprovalDetails.parse(reviewResponse(http,id:approvalID),id:approvalID,workspace:"/tmp/synthetic",revision:UUID())
        precondition(httpReview.review?.ssh==nil && httpReview.review?.windowAllowed==true)
        var malformed=http;malformed.removeValue(forKey:"canonical_request")
        do{_=try LocalApprovalDetails.parse(reviewResponse(malformed,id:approvalID),id:approvalID,workspace:"/tmp/synthetic",revision:UUID());fatalError("HTTP without canonical body accepted")}catch{}
        challenge["schema_id"]="rekey.ssh-sign.v1"
        var ssh:[String:Any] = ["record_type":"rekey.approval.local-review.v1","challenge":challenge,"ssh":["key":"synthetic","host":"unknown-host","bound_host_key":NSNull(),"session_id":NSNull(),"public_key":"c3ludGhldGlj","data_sha256":String(repeating:"ab",count:32),"data_base64":"c3ludGhldGlj","use":["purpose":"authentication","username":"synthetic","unverified_host":NSNull()],"window_allowed":false]]
        let sshReview=try LocalApprovalDetails.parse(reviewResponse(ssh,id:approvalID),id:approvalID,workspace:"/tmp/synthetic",revision:UUID())
        precondition(sshReview.review?.ssh?.use.username=="synthetic" && sshReview.review?.windowAllowed==false)
        ssh["record_type"]="rekey.approval.review.v1"
        do{_=try LocalApprovalDetails.parse(reviewResponse(ssh,id:approvalID),id:approvalID,workspace:"/tmp/synthetic",revision:UUID());fatalError("old review record accepted")}catch{}
        let newestID=UUID().uuidString.lowercased()
        var events:[[String:Any]]=[]
        for i in stride(from:60,through:1,by:-1) {
            events.append(["sequence":i,"event_id":UUID().uuidString.lowercased(),"event_type":"execution.started","outcome":"success","reason_code":"synthetic","created_at_ms":100,"request_id":i==60 ? newestID:UUID().uuidString.lowercased(),"request_context":["connection":"synthetic","caller":"codex","method_class":"read","normalized_path":"/items/\(i)","rule_id":approvalUUID]])
        }
        var terminal=events[0];terminal["sequence"]=61;terminal["event_id"]=UUID().uuidString.lowercased();terminal["event_type"]="execution.finished";events.insert(terminal,at:0)
        let page=try JSONDecoder().decode(AuditPage.self,from:JSONSerialization.data(withJSONObject:["events":events,"snapshot_max_sequence":61,"next_before_sequence":NSNull()]))
        var activity=ActivitySnapshot(nowMs:1000);try activity.ingest(page)
        precondition(activity.rows.count==1 && activity.rows[0].counts.admitted==60 && activity.rows[0].recent.count==50 && activity.rows[0].recent[0].event_type=="execution.finished")
        let rule=ConnectionRule(id:UUID().uuidString.lowercased(),methods:.category("read"),path:"/**",effect:"allow")
        let presetJSON:[String:Any] = ["name":"generic-bearer","origin":"https://example.com","auth":["header_name":"authorization","prefix":"Bearer "],"rules":[try JSONSerialization.jsonObject(with:JSONEncoder().encode(rule))],"allowed_headers":["content-type"],"fixed_headers":[:],"allowed_response_headers":["content-type"],"query_allowlist":NSNull(),"operations":[]]
        let preset=try JSONDecoder().decode(ConnectionPreset.self,from:JSONSerialization.data(withJSONObject:presetJSON))
        let connection=preset.connection(name:"example",credentialID:UUID().uuidString.lowercased())
        let object=try JSONSerialization.jsonObject(with:JSONEncoder().encode(connection))
        let encoded=try JSONSerialization.data(withJSONObject:object)
        let decoded=try JSONDecoder().decode(ConnectionDefinition.self,from:encoded)
        precondition(decoded==connection)
        var mtlsObject=object as! [String:Any];mtlsObject["auth"]=["kind":"mtls"]
        let mtls=try JSONDecoder().decode(ConnectionDefinition.self,from:JSONSerialization.data(withJSONObject:mtlsObject))
        let mtlsRoundtrip=try JSONSerialization.jsonObject(with:JSONEncoder().encode(mtls)) as! [String:Any]
        precondition((mtlsRoundtrip["auth"] as? [String:String])==["kind":"mtls"])
        mtlsObject["auth"]=["kind":"mtls","header_name":"authorization","prefix":"Bearer "]
        do{_=try JSONDecoder().decode(ConnectionDefinition.self,from:JSONSerialization.data(withJSONObject:mtlsObject));fatalError("mixed mTLS/header auth accepted")}catch{}
        let empty:[String:Any] = ["connections":[],"ssh_keys":[],"derived_credentials":[],"policy_sha256":NSNull(),"expires_at_ms":NSNull()]
        let list=try JSONDecoder().decode(ConnectionList.self,from:JSONSerialization.data(withJSONObject:empty));precondition(list.connections.isEmpty)
        var invalid=empty;invalid.removeValue(forKey:"policy_sha256")
        do {_ = try JSONDecoder().decode(ConnectionList.self,from:JSONSerialization.data(withJSONObject:invalid));fatalError("missing editing base accepted")}catch{}
        var missingDerived=empty;missingDerived.removeValue(forKey:"derived_credentials")
        do{_=try JSONDecoder().decode(ConnectionList.self,from:JSONSerialization.data(withJSONObject:missingDerived));fatalError("missing signed T1 field accepted")}catch{}
        let oauthOperation=ConnectionOperation(name:"repository.get",description:"synthetic",method:"GET",path:"/repos/{owner}/{repo}",parameters:.object(["x-rekey-oauth-scopes":.array([.string("repo")])]),read_semantics:nil)
        let oauth=ConnectionPreset(name:"github-oauth",origin:preset.origin,auth:preset.auth,rules:preset.rules,allowed_headers:preset.allowed_headers,fixed_headers:preset.fixed_headers,allowed_response_headers:preset.allowed_response_headers,query_allowlist:preset.query_allowlist,operations:[oauthOperation])
        precondition(OAuthSetup.scopeCeiling(oauth,write:false)==["offline_access","repo"])
        var bound=connection;bound.oauth = .init(provider:"github",client_id:"synthetic-client",scopes:["repo","offline_access"])
        let decodedBound=try JSONDecoder().decode(ConnectionDefinition.self,from:JSONEncoder().encode(bound));precondition(decodedBound==bound)
        var publicWire=Data([0,0,0,11]);publicWire.append(Data("ssh-ed25519".utf8));publicWire.append(Data([0,0,0,32]));publicWire.append(Data(repeating:7,count:32))
        let publicBlob=publicWire.base64EncodedString(),hostRuleID=UUID().uuidString.lowercased()
        let sshKey=SSHKeyDefinition(name:"synthetic-ssh",credential_id:UUID().uuidString.lowercased(),user_public_key:publicBlob,hosts:[.init(host:"github.com",host_key:publicBlob,rule_id:hostRuleID,effect:"deny")],git_signing:"approve")
        let sshObject=try JSONSerialization.jsonObject(with:JSONEncoder().encode(sshKey))
        var externalSSH=sshKey
        externalSSH.approver = .init(kind:"ed25519",keys:["first","second"],threshold:2)
        externalSSH.session_budget = .init(max_signatures:3,max_seconds:45)
        let preservedExternal=try JSONDecoder().decode(SSHKeyDefinition.self,from:JSONEncoder().encode(externalSSH))
        precondition(preservedExternal==externalSSH && preservedExternal.session_budget.max_signatures==3 && preservedExternal.approver.threshold==2)
        precondition(sshKey.publicKeyText=="ssh-ed25519 "+publicBlob)
        precondition(SSHHostDefinition.wireBlob(sshKey.publicKeyText+" synthetic-comment")==publicBlob)
        precondition(SSHHostDefinition.wireBlob("github.com "+sshKey.publicKeyText)==publicBlob)
        precondition(SSHHostDefinition.wireBlob(publicBlob)==publicBlob)
        let preservedSSH=try JSONDecoder().decode(SSHKeyDefinition.self,from:JSONEncoder().encode(sshKey))
        precondition(preservedSSH==sshKey && preservedSSH.hosts[0].rule_id==hostRuleID && preservedSSH.hosts[0].effect=="deny")
        let grant=DerivedCredentialDefinition(name:"synthetic-eks",credential_id:UUID().uuidString.lowercased(),effect:"approve",max_ttl_seconds:900,target:.init(kind:"kubernetes-eks",region:"us-east-1",cluster_id:"build"))
        let grantObject=try JSONSerialization.jsonObject(with:JSONEncoder().encode(grant))
        let signObject:[String:Any] = ["format_version":1,"signer_id":"test","snapshot":["version":1,"expires_at_ms":10000,"connections":[object],"ssh_keys":[sshObject],"derived_credentials":[grantObject]]]
        let sign = "RKPOLICY\0\u{01}"+String(decoding:try JSONSerialization.data(withJSONObject:signObject,options:[.sortedKeys,.withoutEscapingSlashes]),as:UTF8.self)
        var response:[String:Any] = ["metadata":["vault_id":UUID().uuidString.lowercased(),"trust_sha256":String(repeating:"ab",count:32),"public_key":"04"+String(repeating:"ab",count:64),"base_version":NSNull(),"next_version":1,"policy_sha256":String(repeating:"cd",count:32),"changes":[],"connections":[object]],"sign_bytes":sign]
        let draft=try PersonalPolicyDraft(response:JSONSerialization.data(withJSONObject:response),expectedPolicySHA256:nil,expiresAtMs:10000,workspace:"/tmp/synthetic",revision:UUID())
        precondition(draft.connections==[connection] && draft.sshKeys==[sshKey] && draft.derivedCredentials==[grant] && draft.actionsText.contains("synthetic-eks") && draft.actionsText.contains(hostRuleID))
        var derivedEvents:[[String:Any]]=[]
        let derivedRequest=UUID().uuidString.lowercased()
        for (sequence,type,expiry) in [(3,"execution.finished",nil as Int?),(2,"credential.derived_issued",900100),(1,"execution.started",nil)] {
            var context:[String:Any] = ["connection":"synthetic-eks","caller":"codex","target":["kind":"kubernetes-eks","cluster_id":"build","region":"us-east-1"]]
            if let expiry{context["expires_at_ms"]=expiry}
            derivedEvents.append(["sequence":sequence,"event_id":UUID().uuidString.lowercased(),"event_type":type,"outcome":"success","reason_code":"synthetic","created_at_ms":100,"request_id":derivedRequest,"request_context":context])
        }
        let derivedPage=try JSONDecoder().decode(AuditPage.self,from:JSONSerialization.data(withJSONObject:["events":derivedEvents,"snapshot_max_sequence":3,"next_before_sequence":NSNull()]))
        var derivedActivity=ActivitySnapshot(nowMs:1000);try derivedActivity.ingest(derivedPage)
        precondition(derivedActivity.rows.count==1 && derivedActivity.totals.admitted==1 && derivedActivity.rows[0].context?.classification=="临时凭据")
        precondition(derivedActivity.rows[0].recent.count==1 && derivedActivity.rows[0].recent[0].request_context?.expires_at_ms==900100)
        var metadata=response["metadata"] as! [String:Any];var tampered=object as! [String:Any];tampered["origin"]="https://evil.example";metadata["connections"]=[tampered];response["metadata"]=metadata
        do {_ = try PersonalPolicyDraft(response:JSONSerialization.data(withJSONObject:response),expectedPolicySHA256:nil,expiresAtMs:10000,workspace:"/tmp/synthetic",revision:UUID());fatalError("mismatched displayed definition accepted")}catch{}
        let temporary=FileManager.default.temporaryDirectory.appendingPathComponent("rekey-import-contract-"+UUID().uuidString)
        try FileManager.default.createDirectory(at:temporary,withIntermediateDirectories:false,attributes:[.posixPermissions:0o700])
        defer{try? FileManager.default.removeItem(at:temporary)}
        let executable=temporary.appendingPathComponent("synthetic-cli")
        let fixture=temporary.appendingPathComponent("draft-response.json")
        var validResponse=response;metadata["connections"]=[object];validResponse["metadata"]=metadata
        try JSONSerialization.data(withJSONObject:validResponse).write(to:fixture)
        let sshFixture=temporary.appendingPathComponent("ssh-public.json")
        try JSONSerialization.data(withJSONObject:["socket":"/tmp/synthetic-ssh.sock","ssh_keys":[sshObject]]).write(to:sshFixture)
        let script="""
        #!/usr/bin/python3
        import json,sys
        args=sys.argv[1:]
        assert args[:2]==['--state-dir',sys.argv[2]]
        if args[2:]==['policy','draft','--request-stdin']:
            request=json.loads(sys.stdin.read())
            assert set(request)=={'connections','ssh_keys','derived_credentials','expires_at_ms','expected_policy_sha256'}
            assert request['connections'][0]['name']=='example'
            with open(__file__.replace('synthetic-cli','ssh-public.json')) as source:
                expected_ssh=json.load(source)['ssh_keys']
            assert request['ssh_keys']==expected_ssh
            assert request['ssh_keys'][0]['hosts'][0]['effect']=='deny'
            assert request['derived_credentials'][0]['target']=={'kind':'kubernetes-eks','cluster_id':'build','region':'us-east-1'}
            assert request['derived_credentials'][0]['name']=='synthetic-eks'
            assert request['expected_policy_sha256'] is None
            with open(__file__.replace('synthetic-cli','draft-response.json')) as response:
                print(response.read())
            sys.exit(0)
        if args[2:]==['ssh-agent','status']:
            with open(__file__.replace('synthetic-cli','ssh-public.json')) as source:
                print(source.read())
            sys.exit(0)
        if args[2:4]==['ssh-agent','generate']:
            proof=sys.stdin.readline().strip()
            assert proof=='ab'*32 and proof not in args and sys.stdin.read()==''
            assert args[4]=='synthetic literal $(never-run)' and args[5]=='--mode'
            assert args[6] in ['default','ed25519-software','p256-software']
            assert args[7]=='--password-stdin'
            assert args[8:]==(['--presence'] if args[6]=='default' else ['--recovery'] if args[6]=='p256-software' else [])
            with open(__file__.replace('synthetic-cli','ssh-public.json')) as source:
                public=json.load(source)['ssh_keys'][0]
            print(json.dumps({'credential':{'id':public['credential_id'],'label':args[4],'kind':'ssh-ed25519','state':'active','current_version':1},'public_key':public['user_public_key']}))
            sys.exit(0)
        assert args[2]=='import' and args[-2:]==['--presence','--password-stdin']
        proof=sys.stdin.readline().strip()
        assert proof=='ab'*32 and proof not in args
        request=json.loads(sys.stdin.read())
        if '--selections-stdin' in args:
            assert request==[{'key':'SYNTHETIC_KEY','label':'synthetic label'}]
            print(json.dumps({'entries':[{'key':'SYNTHETIC_KEY','credential':{'id':'00000000-0000-4000-8000-000000000001','label':'synthetic label','kind':'opaque-token','state':'active','current_version':1}}],'unsupported':[]}))
        else:
            assert '--rewrite-stdin' in args
            assert request==[{'key':'SYNTHETIC_KEY','connection':'synthetic','base_url_variable':'SYNTHETIC_BASE_URL'}]
            print(json.dumps({'backup':'/tmp/synthetic.env.rekey-backup'}))
        """
        try Data(script.utf8).write(to:executable);try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:executable.path)
        let client=CLI(binary:executable,stateDirectory:temporary.path),path=temporary.appendingPathComponent("missing-source.env").path
        let requestedDraft=try client.personalPolicyDraft(connections:[connection],sshKeys:[sshKey],derivedCredentials:[grant],expectedPolicySHA256:nil,expiresAtMs:10000,revision:UUID())
        precondition(requestedDraft.derivedCredentials==[grant] && requestedDraft.sshKeys==[sshKey])
        let status=try client.sshStatus();precondition(status.socket=="/tmp/synthetic-ssh.sock" && status.ssh_keys==[sshKey])
        for mode in SSHKeyMode.allCases {
            let receipt=try client.generateSSHKey(label:"synthetic literal $(never-run)",mode:mode,proof:String(repeating:"ab",count:32),recovery:mode == .p256Software,presence:mode == .secureEnclave)
            precondition(receipt.public_key==publicBlob && receipt.credential.id==sshKey.credential_id)
        }
        let receipt=try client.importSelected(path:path,selections:[.init(key:"SYNTHETIC_KEY",label:"synthetic label")],proof:String(repeating:"ab",count:32))
        precondition(receipt.entries.count==1 && receipt.entries[0].key=="SYNTHETIC_KEY")
        let rewritten=try client.rewriteImported(path:path,replacements:[.init(key:"SYNTHETIC_KEY",connection:"synthetic",base_url_variable:"SYNTHETIC_BASE_URL")],proof:String(repeating:"ab",count:32))
        precondition(rewritten.backup=="/tmp/synthetic.env.rekey-backup" && !FileManager.default.fileExists(atPath:path))
        print("Connection App contracts passed: routing, bounded authentication context reuse, roundtrip, signed editing base, exact displayed definitions, OAuth scopes, T1 target/expiry, full HTTP/SSH/T1 draft stdin, preserved host rules and SSH generation proof boundaries.")
    }
    static func reviewResponse(_ review:[String:Any],id:String)throws->Data {
        let raw=try JSONSerialization.data(withJSONObject:review,options:[.sortedKeys,.withoutEscapingSlashes])
        let digest=SHA256.hash(data:Data("RKREVIEW\0\u{1}".utf8)+raw).map{String(format:"%02x",$0)}.joined()
        return try JSONSerialization.data(withJSONObject:["metadata":["record_type":"rekey.approval.local-review.v1","approval_request_id":id,"review_sha256":digest,"state":"pending","body_len":raw.count],"review_json":String(decoding:raw,as:UTF8.self)])
    }
}
