const debug = require('debug')('node-vault')

const request = require('request-promise-native')
// https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
const aws4 = require('aws4')

// constants
const EC2_METADATA_BASE_URL = 'http://169.254.169.254/latest/'
const ECS_METADATA_BASE_URL = 'http://169.254.170.2'

// cache reference to avoid multiple network calls to fetch the role
let role
const getEc2Role = async () => {
  if (role) {
    debug(`getEc2Role() - using cached role ${role}`)
    return role
  } else {
    const roleRequestUrl = `${EC2_METADATA_BASE_URL}meta-data/iam/security-credentials/`
    role = await request(roleRequestUrl)
    debug(`getEc2Role() - called ${roleRequestUrl} and got role ${role}`)
    return role
  }
}

// obtains, parses and formats the relevant data
// from the ECS or EC2 instance metadata service
const getCredentials = async () => {
  // Elastic Container Service
  if (process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) {
    const credentialsRequestUrl = `${ECS_METADATA_BASE_URL}${process.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}`
    debug(`Getting ECS credentials from ${credentialsRequestUrl}`)
    const credentials = await request(credentialsRequestUrl)
      .then(JSON.parse)
    debug(`Received credentials for role ${credentials.RoleArn}`)
    return credentials

  // EC2
  } else {
    // get credentials using role
    const ec2Role = await getEc2Role()
    const credentialsRequestUrl = `${EC2_METADATA_BASE_URL}meta-data/iam/security-credentials/${ec2Role}`
    debug(`Getting EC2 credentials from ${credentialsRequestUrl}`)
    const credentials = await request(credentialsRequestUrl)
      .then(JSON.parse)
    debug(`Received credentials for role ${credentials.RoleArn}`)
    return credentials
  }
}

// creates a signed request to the GetCallerIdentity method
// from the STS service by inferring credentials data from
// the ECS or EC2 instance metadata service and signing it with
// AWS signature version 4
const getSignedIamRequest = async () => {
  // get instance data
  const credentials = await getCredentials()

  // construct request
  const url = 'https://sts.amazonaws.com/'
  const body = 'Action=GetCallerIdentity&Version=2011-06-15'
  // TODO: rethink 'X-Vault-AWS-IAM-Server-ID' implementation (env variable?)
  const headers = {
    // 'X-Vault-AWS-IAM-Server-ID': '<vault-id>'
  }
  const req = {
    service: 'sts',
    region: 'us-east-1', // https://github.com/hashicorp/vault-ruby/pull/161#issuecomment-355723269
    doNotModifyHeaders: false, // DISABLED temporal workaround to https://github.com/hashicorp/vault/issues/2810#issuecomment-306530386
    body,
    headers
  }

  // sign request
  const { AccessKeyId, SecretAccessKey, Token } = credentials
  const accessKeyId = AccessKeyId
  const secretAccessKey = SecretAccessKey
  const sessionToken = Token
  aws4.sign(req, { accessKeyId, secretAccessKey, sessionToken })

  // Content-Length header workaround for Vault v0.9.1 and lower
  // https://github.com/hashicorp/vault/issues/3763/
  req.headers['Content-Length'] = req.headers['Content-Length'].toString()

  // construct request for vault
  return {
    iam_http_request_method: 'POST',
    iam_request_url: Buffer
      .from(url).toString('base64'),
    iam_request_body: Buffer
      .from(body).toString('base64'),
    iam_request_headers: Buffer
      .from(JSON.stringify(req.headers)).toString('base64')
  }
}

const awsIamLogin = async (vault, options = {}) => {
  // execute login operation
  const vaultRequest = await getSignedIamRequest()

  // the role to use with Vault might be different than the role used by AWS
  vaultRequest.role = options.vaultRole || process.env.VAULT_ROLE || await getEc2Role()

  const authResult = await vault.awsIamLogin(vaultRequest)

  // login with the returned token into node-vault
  vault.login(authResult.auth.client_token)

  // return the authenticated module
  return vault
}

// creates a logged in instance of node-vault
module.exports = awsIamLogin
