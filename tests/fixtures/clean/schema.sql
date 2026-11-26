ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can only view own profile" ON users
  FOR SELECT USING (auth.uid() = user_id);
