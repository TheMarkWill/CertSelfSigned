import forge from 'node-forge';
import os from 'os';
import fs from 'fs';
import path from 'path';
import { RootCertificate } from './rootCertificate';

/**
 * Models to create a cert
 *
 * https://github.com/jsumners/self-cert/blob/master/index.js
 * https://github.com/MikeKovarik/selfsigned-ca/blob/master/examples/simple.js
 * https://www.npmjs.com/package/node-forge
 * https://github.com/julie-ng/nodejs-certificate-auth
 * https://knowledge.digicert.com/generalinformation/INFO2824.html
 * https://www.ibm.com/docs/en/external-auth-server/2.4.3?topic=securing-x509-extensions
 */

export interface EntityOptions {
  commonName?: string;
  countryName?: string;
  stateName?: string;
  locality?: string;
  orgName?: string;
  shortName?: string;
}

export interface OptionsCert {
  expiryOn: Date;
  bits: 2048 | 4096;
  subject?: EntityOptions;
}

class ClientCertificate {
  private rsa = forge.pki.rsa;

  private pki = forge.pki;

  private now = new Date();

  public keyPair: forge.pki.KeyPair;

  public cert: forge.pki.Certificate;

  constructor(private options: OptionsCert, private rootCA: RootCertificate) {
    if (!this.options.expiryOn) {
      this.options.expiryOn = new Date(
        this.now.getFullYear() + 5,
        this.now.getMonth() + 1,
        this.now.getDate()
      );
    }

    if (!this.options.subject) this.options.subject = {};

    this.keyPair = this.generateKeyPar();
    this.cert = this.generateCert();
  }

  private generateKeyPar() {
    const keys = this.rsa.generateKeyPair(this.options.bits || 4096);

    return keys;
  }

  private generateCert() {
    const cert = this.pki.createCertificate();

    cert.publicKey = this.keyPair.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = this.now;
    cert.validity.notAfter = this.options.expiryOn;

    // TODO: Change to options and not default value
    const subject = [
      {
        name: 'commonName',
        value: this.options?.subject?.commonName || os.hostname()
      },
      {
        name: 'countryName',
        value: this.options?.subject?.countryName || 'US'
      },
      {
        name: 'stateOrProvinceName',
        value: this.options?.subject?.stateName || 'Georgia'
      },
      {
        name: 'localityName',
        value: this.options?.subject?.locality || 'Atlanta'
      },
      {
        name: 'organizationName',
        value: this.options?.subject?.orgName || 'None'
      },
      { shortName: 'OU', value: this.options?.subject?.shortName || 'example' }
    ];

    cert.setSubject(subject);
    cert.setIssuer(this.rootCA.cert.subject.attributes);

    cert.setExtensions([
      {
        name: 'basicConstraints',
        cA: true
      },
      {
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true
      },
      {
        name: 'subjectKeyIdentifier'
      }
    ]);

    cert.sign(this.rootCA.privateKey);

    return cert;
  }

  public certToString() {
    return {
      cert: this.pki.certificateToPem(this.cert),
      publicKey: this.pki.publicKeyToPem(this.keyPair.publicKey),
      privateKey: this.pki.privateKeyToPem(this.keyPair.privateKey)
    };
  }

  public writeCertificate(folderPath: string, fileName: string) {
    const certString = this.certToString();

    fs.writeFileSync(
      path.resolve(folderPath, `${fileName}.cert`),
      certString.cert
    );
    fs.writeFileSync(
      path.resolve(folderPath, `${fileName}.key`),
      certString.privateKey
    );
    fs.writeFileSync(
      path.resolve(folderPath, `${fileName}.pub.key`),
      certString.publicKey
    );
  }
}

export { ClientCertificate };
