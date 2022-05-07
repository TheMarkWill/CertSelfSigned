import { RootCertificate } from "../src/rootCertificate";

const rootCANEW = new RootCertificate( {
    expiryOn: new Date('2030-01-02'),
    bits: 4096,
    subject: {
      commonName: 'api.hoopay.com.br',
      countryName: 'BR',
      stateName: 'MT',
      locality: 'Primavera do Leste',
      orgName: 'HooPay ME',
      shortName: 'IT'
    }
  });

  console.log(rootCANEW.certToString())

  rootCANEW.writeCertificate(__dirname, 'server')
