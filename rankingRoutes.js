const express = require('express');
const { autenticarToken, autorizarCargo } = require('../middleware/auth');

module.exports = (pool) => {
  const router = express.Router();

  router.get('/ranking', autenticarToken, autorizarCargo('admin','gerente'), async (req, res) => {

    let query = `
      SELECT l.id, l.nome,
      ROUND((AVG(a.nota_atendimento)+AVG(a.nota_organizacao)+AVG(a.nota_produtos))/3,2) as media_geral
      FROM lojas l
      JOIN avaliacoes a ON l.id=a.loja_id
    `;

    let params = [];

    if(req.user.cargo === 'gerente'){
      // MySQL usa ? em vez de $1
      query += ' WHERE l.id = ?';
      params.push(req.user.loja_id);
    }

    query += ' GROUP BY l.id ORDER BY media_geral DESC';

    try {
      // Extraindo [rows] diretamente, padrão do mysql2/promise
      const [rows] = await pool.query(query, params);
      res.json(rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Erro ao buscar ranking' });
    }
  });

  router.get('/media-global', autenticarToken, autorizarCargo('admin','gerente'), async (req,res)=>{
    let query = `
      SELECT ROUND((AVG(nota_atendimento)+AVG(nota_organizacao)+AVG(nota_produtos))/3,2) as media_global,
      COUNT(*) as total
      FROM avaliacoes
    `;

    let params = [];

    if(req.user.cargo==='gerente'){
      // MySQL usa ? em vez de $1
      query += ' WHERE loja_id = ?';
      params.push(req.user.loja_id);
    }

    try {
      const [rows] = await pool.query(query, params);
      res.json(rows[0]);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: 'Erro ao buscar média global' });
    }
  });

  return router;
};