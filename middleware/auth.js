const jwt = require('jsonwebtoken');

function autenticarToken(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    return res.status(401).json({ message: 'Token não fornecido' });
  }

  // Extrai o token ignorando a palavra "Bearer "
  const token = authHeader.split(' ')[1];

  // Verifica a validade e a assinatura do Token
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido ou expirado' });
    }
    
    // Salva os dados do usuário na requisição para as próximas etapas
    req.user = user;
    next();
  });
}

function autorizarCargo(...cargos) {
  return (req, res, next) => {
    // Blindagem: Garante que req.user existe antes de tentar ler req.user.cargo
    if (!req.user || !cargos.includes(req.user.cargo)) {
      return res.status(403).json({ message: 'Acesso negado' });
    }
    next();
  };
}

module.exports = { autenticarToken, autorizarCargo };