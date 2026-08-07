const express = require('express');
const { autenticarToken, autorizarCargo } = require('../middleware/auth');

module.exports = (pool) => {
  const router = express.Router();

  router.get('/avaliacoes-detalhadas', autenticarToken, autorizarCargo('admin','gerente'), async (req,res)=>{
    let query = `
      SELECT l.nome, a.nota_atendimento, a.nota_organizacao, a.nota_produtos, a.comentario, a.created_at
      FROM avaliacoes a
      JOIN lojas l ON l.id=a.loja_id
    `;

    let params=[];

    if(req.user.cargo==='gerente'){
      // MySQL usa ? em vez de $1
      query += ' WHERE l.id = ?';
      params.push(req.user.loja_id);
    }

    query += ' ORDER BY a.id DESC';

    try {
      // Extraindo [rows] diretamente, padrão do mysql2/promise
      const [rows] = await pool.query(query, params);
      res.json(rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Erro ao buscar avaliações detalhadas' });
    }
  });

  return router;
};
