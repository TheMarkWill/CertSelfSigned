import forge from 'node-forge';
import os from 'os';
import fs from 'fs';
import path from 'path';

interface EntityOptions {
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

class RootCertificate {
  private createdOn: Date;

  private expiryOn: Date;

  public cert: forge.pki.Certificate;

  public privateKey: forge.pki.PrivateKey;

  public publicKey?: forge.pki.PublicKey;

  constructor(options: OptionsCert | string, privateKeyInput: string) {
    if (options instanceof Object) {
      this.createdOn = new Date();
      if (!options.expiryOn) {
        options.expiryOn = new Date(
          this.createdOn.getFullYear() + 5,
          this.createdOn.getMonth() + 1,
          this.createdOn.getDate()
        );
      }

      this.expiryOn = options.expiryOn;

      const { privateKey, publicKey } = this.generateKeyPar(options.bits);

      this.privateKey = privateKey;
      this.publicKey = publicKey;

      const { cert } = this.generateCert(options);

      this.cert = cert;
    } else {
      this.cert = forge.pki.certificateFromPem(options);

      this.createdOn = this.cert.validity.notBefore;
      this.expiryOn = this.cert.validity.notAfter;

      this.privateKey = forge.pki.privateKeyFromPem(privateKeyInput);
    }
  }

  private generateKeyPar(bits: 2048 | 4096 = 4096) {
    const keys = forge.pki.rsa.generateKeyPair(bits);

    return keys;
  }

  private generateCert(options: OptionsCert) {
    const cert = forge.pki.createCertificate();

    cert.serialNumber = '01';
    cert.version = 1;
    cert.validity.notBefore = this.createdOn;
    cert.validity.notAfter = this.expiryOn;

    // TODO: Change to options and not default value
    const subject = [
      {
        name: 'commonName',
        value: options?.subject?.commonName || os.hostname()
      },
      {
        name: 'countryName',
        value: options?.subject?.countryName || 'US'
      },
      {
        name: 'stateOrProvinceName',
        value: options?.subject?.stateName || 'Georgia'
      },
      {
        name: 'localityName',
        value: options?.subject?.locality || 'Atlanta'
      },
      {
        name: 'organizationName',
        value: options?.subject?.orgName || 'None'
      },
      { shortName: 'OU', value: options?.subject?.shortName || 'example' }
    ];

    cert.setIssuer(subject);
    cert.setSubject(subject);

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

    cert.sign(this.privateKey);

    return { cert };
  }

  public certToString() {
    return {
      cert: forge.pki.certificateToPem(this.cert),
      publicKey: this.publicKey && forge.pki.publicKeyToPem(this.publicKey),
      privateKey: forge.pki.privateKeyToPem(this.privateKey)
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

    if (certString.publicKey) {
      fs.writeFileSync(
        path.resolve(folderPath, `${fileName}.pub.key`),
        certString.publicKey
      );
    }
  }
}

export { RootCertificate };
