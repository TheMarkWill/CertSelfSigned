import forge from 'node-forge';
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

  constructor(options: OptionsCert);

  constructor(certificatePem: string, privateKeyPem: string);

  constructor(
    certificatePem: string,
    privateKeyPem: string,
    publicKeyPem?: string
  );

  constructor(
    optionsOrCertPem: OptionsCert | string,
    privateKeyPem?: string,
    publicKeyPem?: string
  ) {
    if (optionsOrCertPem instanceof Object) {
      const options = optionsOrCertPem;
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
      const certPem = optionsOrCertPem;
      this.cert = forge.pki.certificateFromPem(certPem);

      this.createdOn = this.cert.validity.notBefore;
      this.expiryOn = this.cert.validity.notAfter;

      this.privateKey = forge.pki.privateKeyFromPem(privateKeyPem || '');
      this.publicKey = forge.pki.publicKeyFromPem(publicKeyPem || '');
    }
  }

  private generateKeyPar(bits: 2048 | 4096 = 4096) {
    const keys = forge.pki.rsa.generateKeyPair(bits);

    return keys;
  }

  private generateCert(options: OptionsCert) {
    const cert = forge.pki.createCertificate();

    // To generate as created a keyPar, in this case have public key instanced
    cert.publicKey = this.publicKey as forge.pki.PublicKey;
    cert.serialNumber = '01';
    cert.version = 1;
    cert.validity.notBefore = this.createdOn;
    cert.validity.notAfter = this.expiryOn;

    // TODO: Change to options and not default value
    const subject = [
      {
        name: 'commonName',
        value: options?.subject?.commonName || 'None'
      },
      {
        name: 'countryName',
        value: options?.subject?.countryName || 'None'
      },
      {
        name: 'stateOrProvinceName',
        value: options?.subject?.stateName || 'None'
      },
      {
        name: 'localityName',
        value: options?.subject?.locality || 'None'
      },
      {
        name: 'organizationName',
        value: options?.subject?.orgName || 'None'
      },
      { shortName: 'OU', value: options?.subject?.shortName || 'None' }
    ];

    cert.setIssuer(subject);
    cert.setSubject(subject);

    cert.sign(this.privateKey);

    return { cert };
  }

  public certToString() {
    return {
      cert: forge.pki.certificateToPem(this.cert),
      privateKey: forge.pki.privateKeyToPem(this.privateKey),
      publicKey: this.publicKey && forge.pki.publicKeyToPem(this.publicKey)
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

function loadRootCertificateFromPemFile(
  certPathPem: string,
  privateKeyPathPem: string,
  publicKeyPathPem?: string
): RootCertificate {
  const cert = fs.readFileSync(certPathPem).toString();
  const privateKey = fs.readFileSync(privateKeyPathPem).toString();
  const publicKey = publicKeyPathPem
    ? fs.readFileSync(publicKeyPathPem).toString()
    : undefined;

  return new RootCertificate(cert, privateKey, publicKey);
}

export { RootCertificate, loadRootCertificateFromPemFile };
