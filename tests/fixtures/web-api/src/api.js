// Synthetic insecure fixture: no real service or data.
app.get("/accounts/:accountId", requireLogin, async (req, res) => {
  const account = await db.accounts.findById(req.params.accountId);
  res.json(account);
});
