function decodeUplink(input) {
  // Vérifie que nous avons bien 6 octets (3 pour lat + 3 pour lon)
  if (input.bytes.length !== 6) {
    return {
      errors: ['Invalid payload length'],
    };
  }

  // Décode la latitude (3 premiers octets)
  let latitude = (input.bytes[0] << 16) | (input.bytes[1] << 8) | input.bytes[2];

  // Décode la longitude (3 derniers octets)
  let longitude = (input.bytes[3] << 16) | (input.bytes[4] << 8) | input.bytes[5];

  // Conversion en degrés décimaux (division par 10000)
  latitude = latitude / 10000;
  longitude = longitude / 10000;

  // Retourne l'objet JSON formaté
  return {
    data: {
      latitude: latitude,
      longitude: longitude,
      timestamp: new Date().toISOString()
    }
  };
}
