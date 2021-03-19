<cfcomponent accessors="true" initmethod="init" displayname="AWS SES api component">

  <cfproperty name="secretKey" type="string">
  <cfproperty name="accessId" type="string">
  <cfproperty name="region" type="string">

  <cffunction name="init">
    <cfargument name="accessId" required="true"  type="string">
    <cfargument name="secretKey" required="true" type="string">
    <cfargument name="region" required="false" type="string" default="us-east-1">
    
    <cfset setAccessId(arguments.accessId)>
    <cfset setSecretKey(arguments.secretKey)>
    <cfset setRegion(arguments.region)>
    <cfreturn this>
  </cffunction>

  <cffunction name="getAwsRequestAuthorization" access="private" description="Creates aws version 4 signature">
    <cfargument name="accessId" required="true"  type="string" default="#getAccessId()#">
    <cfargument name="secretKey" required="true" type="string" default="#getSecretKey()#">
    <cfargument name="region" required="true" type="string" default="#getRegion()#">
    <cfargument name="service" required="true" type="string">
    <cfargument name="method" required="true" type="string">
    <cfargument name="host" required="true" type="string">
    <cfargument name="uri" required="false" type="string" default="">
    <cfargument name="queryString" required="false" type="string" default="">
    <cfargument name="timeStamp" required="false" type="date" default="#now()#">
    <cfargument name="payload" required="false" type="string" default="">
    <cfargument name="unsignedPayload" required="false" type="boolean" default="false">
    <cfargument name="signatureOnly" required="false" type="boolean" default="false">
    <cfargument name="signDate" required="false" type="boolean" default="true">
    
    <cfset local.timeIso=getIsoTimeString(arguments.timeStamp)>
    <cfset local.dateIso=getIsoDateString(arguments.timeStamp)>

    <cfset local.sortedQueryString=sortQueryString(arguments.queryString)>

    <cfif arguments.unsignedPayload>
      <cfset local.signedPayload="UNSIGNED-PAYLOAD">
    <cfelse>
      <cfset local.signedPayload=lcase(hash(arguments.payload,'sha256'))>
    </cfif>

    <cfif arguments.signDate>
      <cfset local.signedHeadersString="host;x-amz-date">
    <cfelse>
      <cfset local.signedHeadersString="host">
    </cfif>

    <cfset local.canonicalRequestParts=[ 
      arguments.method, "/#arguments.uri#" , 
      local.sortedQueryString, 
      "host:#arguments.host#" , 
      "" , 
      local.signedHeadersString , 
      local.signedPayload 
    ]>

    <cfif arguments.signDate>
      <cfset arrayInsertAt(local.canonicalRequestParts,5,"x-amz-date:#local.timeIso#")>
    </cfif>
    
    <cfset local.canonicalRequest=arrayToList(local.canonicalRequestParts, chr( 10 ) )>
    <cfset local.signedCanonicalRequest=lcase(hash(local.canonicalRequest,'sha256'))>
    <cfset local.credentialsScopeString="#local.dateIso#/#arguments.region#/#arguments.service#/aws4_request">

    <cfset local.stringToSignParts=[ 
      "AWS4-HMAC-SHA256" , 
      local.timeIso, 
      local.credentialsScopeString, 
      local.signedCanonicalRequest 
    ]>

    <cfset local.stringToSign=arrayToList(local.stringToSignParts, chr( 10 ))>
    <cfset local.signingKey=getSignatureKey( arguments.secretKey, local.dateIso, arguments.region, arguments.service )>
    <cfset local.signature=lCase(HMAC(local.stringToSign,binaryDecode(local.signingKey,'hex'),"hmacsha256"))>

    <cfif arguments.signatureOnly>
      <cfreturn local.signature>
    </cfif>
    <cfreturn "AWS4-HMAC-SHA256 Credential=#arguments.accessID#/#local.dateIso#/#arguments.region#/#arguments.service#/aws4_request,SignedHeaders=#local.signedHeadersString#,Signature=#local.signature#">
  </cffunction>

  <cffunction name="sortQueryString" access="private" description="Aws version 4 signature needs query string parameters in sorted form">
    <cfargument name="queryString" required="true" type="string">

    <cfset local.queryParts=listToArray(arguments.queryString,'&')>
    <cfset ArraySort(local.queryParts,"textnocase", "asc")>

    <cfreturn arrayToList(local.queryParts,"&")>
  </cffunction>


  <cffunction name="getSignatureKey" access="private" description="Signing process to create signed key for aws version 4 signature">
    <cfargument name="secretKey" required="true">
    <cfargument name="dateStamp" required="true">
    <cfargument name="regionName" required="true">
    <cfargument name="serviceName" required="true">
    <cfset local.kDate=lCase(HMAC(arguments.dateStamp,"AWS4" & arguments.secretKey,"hmacsha256"))>
    <cfset local.kRegion=lCase(HMAC(arguments.regionName,binaryDecode(local.kDate,'hex'),"hmacsha256"))>
    <cfset local.kService=lCase(HMAC(arguments.serviceName,binaryDecode(local.kRegion,'hex'),"hmacsha256"))>
    <cfset local.kSigning=lCase(HMAC("aws4_request",binaryDecode(local.kService,'hex'),"hmacsha256"))>
    <cfreturn local.kSigning>
  </cffunction>

  <cffunction name="getIsoTimeString" access="private" description="Converts time into iso format">
    <cfargument name="datetime" type="date" required="true">
    <cfset local.datetime=dateConvert( "local2utc", arguments.datetime )>
    <cfreturn ( dateFormat( local.datetime, "yyyymmdd" ) & "T" & timeFormat( local.datetime, "HHmmss" ) & "Z" )>
  </cffunction>

  <cffunction name="getIsoDateString" access="private" description="Converts time to iso date format">
    <cfargument name="datetime" type="date" required="true">
    <cfset local.datetime=dateConvert( "local2utc", arguments.datetime )>
    <cfreturn (dateFormat( local.datetime, "yyyymmdd" ))>
  </cffunction>

  <cffunction name="urlEncodeForAws" description="Things to be done to a coldfusion url encoded string (using encodeForURL) to get supported by aws">
    <cfargument name="value" required="true" type="string">

    <cfset local.urlEncoded = encodeForURL(arguments.value)>

    <!--- Reverting url encoded AWS reserved character ~ --->
    <cfset local.urlEncoded = replace(local.urlEncoded,"%7E","~","ALL")>

    <!--- Change + into %20 since coldfusion encodes spaces into + sign which is not supported by aws --->
    <cfset local.urlEncoded = replace(local.urlEncoded,"+","%20","ALL")>

    <cfreturn local.urlEncoded>
  </cffunction>

  <cffunction name="createErrorObject" access="private" description="To create a structure with error response from cfhttp result">
    <cfargument name="httpResult" required="true" type="struct">
    <cfreturn {
      response = arguments.httpResult.fileContent,
      responseStatus = arguments.httpResult.Statuscode
    }>
  </cffunction>

  <cffunction name="sesSendEmail" access="public" description="Send mail using aws ses service">
    <cfargument name="from" required="true" type="string">
    <cfargument name="to" required="true" type="string">
    <cfargument name="subject" required="true" type="string">
    <cfargument name="body" required="true" type="string">
    <cfargument name="accessId" required="false"  type="string" default="#getAccessId()#">
    <cfargument name="secretKey" required="false" type="string" default="#getSecretKey()#">
    <cfargument name="region" required="true" type="string" default="#getRegion()#">
    
    <cfset local.timestamp = now()>
    <cfset local.sourceUrlEncoded = urlEncodeForAws(arguments.from)>
    <cfset local.destinationUrlEncoded = urlEncodeForAws(arguments.to)>
    <cfset local.subjectUrlEncoded = urlEncodeForAws(arguments.subject)>
    <cfset local.bodyUrlEncoded = urlEncodeForAws(arguments.body)>

    <cfset local.queryString = "Destination.ToAddresses.member.1=#local.destinationUrlEncoded#&Action=SendEmail&Message.Body.Text.Data=#local.bodyUrlEncoded#&Message.Subject.Data=#local.subjectUrlEncoded#&Source=#local.sourceUrlEncoded#">

    <cfset local.host = "email.#arguments.region#.amazonaws.com">

    <cfset local.signature = getAwsRequestAuthorization(
        accessId=arguments.accessId,
        secretKey=arguments.secretKey,
        region=arguments.region,
        service='ses',
        method='POST',
        host=local.host,
        timeStamp=local.timestamp,
        payload=local.queryString
    )>
    <cfhttp method="POST" url="https://#local.host#" result="local.httpResult">
        <cfhttpparam type="header" name="Authorization" value="#local.signature#">
        <cfhttpparam type="header" name="Host" value="#local.host#">
        <cfhttpparam type="header" name="Content-Type" value="application/x-www-form-urlencoded">
        <cfhttpparam type="header" name="X-Amz-Date" value="#getIsoTimeString(local.timestamp)#">
        <cfhttpparam type="body" value="#local.queryString#">
    </cfhttp>

    <cfreturn {
      success = (local.httpResult.Responseheader.status_code == 200),
      errorObject = (local.httpResult.Responseheader.status_code == 200)?
                    false:createErrorObject(local.httpResult)
    }>
  </cffunction>

  <cffunction name="s3Putobject" access="public" description="Uploads a given file into s3 in specified key(directory)">
    <cfargument name="bucket" required="true" type="string">
    <cfargument name="key" required="true" type="string">
    <cfargument name="file" required="true" type="any">
    <cfargument name="contentType" required="false">
    <cfargument name="accessId" required="false"  type="string" default="#getAccessId()#">
    <cfargument name="secretKey" required="false" type="string" default="#getSecretKey()#">
    <cfargument name="region" required="true" type="string" default="#getRegion()#">

    <cfif isSimpleValue(arguments.file)>
      <cfset arguments.file = fileReadBinary(arguments.file)>
    <cfelseif NOT isBinary(arguments.file)>
      <cfthrow message="Argument file of s3Putobject must be a valid file(use fileReadBinary) or path to a file ">
    </cfif>

    <cfset local.timestamp = now()>
    
    <cfif arguments.region EQ "us-east-1">
      <cfset local.host = "#arguments.bucket#.s3.amazonaws.com">
    <cfelse>
      <cfset local.host = "#arguments.bucket#.s3-#arguments.region#.amazonaws.com">
    </cfif>

    <cfset local.signature = getAwsRequestAuthorization(
        accessId=arguments.accessId,
        secretKey=arguments.secretKey,
        region=arguments.region,
        service='s3',
        method='PUT',
        host=local.host,
        uri=arguments.key,
        timeStamp=local.timestamp,
        unsignedPayload=true
    )>

    <cfhttp method="put" url="https://#local.host#/#arguments.key#" result="local.httpResult">
      <cfhttpparam type="header" name="Authorization" value="#local.signature#">
      <cfhttpparam type="header" name="Host" value="#local.host#">
      <cfif structKeyExists(arguments,'contentType')>
        <cfhttpparam type="header" name="Content-Type" value="image/jpeg">
      </cfif>
      <cfhttpparam type="header" name="X-Amz-content-sha256" value="UNSIGNED-PAYLOAD">
      <cfhttpparam type="header" name="X-Amz-Date" value="#getIsoTimeString(local.timestamp)#">
      <cfhttpparam type="body" value="#arguments.file#">
    </cfhttp>


    <cfreturn {
      success = (local.httpResult.Responseheader.status_code == 200),
      errorObject = (local.httpResult.Responseheader.status_code == 200)?
                    false:createErrorObject(local.httpResult)
    }>
  </cffunction>

  <cffunction name="s3getObjectUrl" access="public" description="Generates a presigned url to get a file from s3 for the specified key(directory)">
    <cfargument name="bucket" required="true" type="string">
    <cfargument name="key" required="true" type="string">
    <cfargument name="accessId" required="false"  type="string" default="#getAccessId()#">
    <cfargument name="secretKey" required="false" type="string" default="#getSecretKey()#">
    <cfargument name="region" required="true" type="string" default="#getRegion()#">
    <cfargument name="expires" required="false" type="numeric" default="3600">
    <cfargument name="isMethodHead" required="false" type="boolean" default="false">

    <cfset local.timestamp = now()>
    <cfset local.dateIso=getIsoDateString(local.timeStamp)>

    <cfif arguments.region EQ "us-east-1">
      <cfset local.host = "#arguments.bucket#.s3.amazonaws.com">
    <cfelse>
      <cfset local.host = "#arguments.bucket#.s3-#arguments.region#.amazonaws.com">
    </cfif>

    <cfset local.credentialsString=urlEncodeForAws("#arguments.accessId#/#local.dateIso#/#arguments.region#/s3/aws4_request")>
    <cfset local.headersString=urlEncodeForAws("host")>
    
    <cfset local.queryString = arrayToList([
      "X-Amz-Algorithm=AWS4-HMAC-SHA256",
      "X-Amz-Credential=#local.credentialsString#",
      "X-Amz-Date=#getIsoTimeString(local.timestamp)#",
      "X-Amz-SignedHeaders=#local.headersString#",
      "X-Amz-Expires=#arguments.expires#"
    ],"&")>

    
    <cfset local.signature = getAwsRequestAuthorization(
        accessId=arguments.accessId,
        secretKey=arguments.secretKey,
        region=arguments.region,
        service='s3',
        method=arguments.isMethodHead?'HEAD':'GET',
        host=local.host,
        uri=arguments.key,
        queryString=local.queryString,
        timeStamp=local.timestamp,
        unsignedPayload=true,
        signatureOnly=true,
        signDate=false
    )>

    <cfreturn "https://#local.host#/#arguments.key#?#local.queryString#&X-Amz-Signature=#local.signature#">    
  </cffunction>
  
  <cffunction name="s3downloadObject" access="public" description="Download a file from s3 for the specified key(directory) into local directory">
    <cfargument name="bucket" required="true" type="string">
    <cfargument name="key" required="true" type="string">
    <cfargument name="path" required="true" type="string">
    <cfargument name="fileName" required="true" type="string">
    <cfargument name="accessId" required="false"  type="string" default="#getAccessId()#">
    <cfargument name="secretKey" required="false" type="string" default="#getSecretKey()#">
    <cfargument name="region" required="true" type="string" default="#getRegion()#">

    <cfif NOT directoryExists(arguments.path)>
      <cfthrow message="Path provided doesnt exists(#arguments.path#)">
    </cfif>

    <cfset local.objectUrl = s3getObjectUrl(
      bucket = arguments.bucket,
      key = arguments.key,
      accessId = arguments.accessId,
      secretKey = arguments.secretKey,
      region = arguments.region
    )>
    <cfhttp method="GET" url="#local.objectUrl#" getAsBinary="yes" path="#arguments.path#" file="#arguments.fileName#">
		</cfhttp>
  </cffunction>

  <cffunction name="s3objectExists" access="public" description="To check whether an object in s3 exist or not">
    <cfargument name="bucket" required="true" type="string">
    <cfargument name="key" required="true" type="string">
    <cfargument name="accessId" required="false"  type="string" default="#getAccessId()#">
    <cfargument name="secretKey" required="false" type="string" default="#getSecretKey()#">
    <cfargument name="region" required="true" type="string" default="#getRegion()#">
    <cfargument name="expires" required="false" type="numeric" default="3600">

    <cfset local.objectUrl = s3getObjectUrl(
      bucket = arguments.bucket,
      key = arguments.key,
      accessId = arguments.accessId,
      secretKey = arguments.secretKey,
      region = arguments.region,
      isMethodHead = true
    )>

    <cfhttp method="HEAD" url="#local.objectUrl#" result="local.httpResult"></cfhttp>  

    <cfreturn local.httpResult.Responseheader.status_code == 200>
  </cffunction>
</cfcomponent>