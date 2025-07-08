import 'dotenv/config';
import app from './app.js';
import DB from './database/index.db.js';

const PORT = process.env.PORT;

new DB().connectMongo().then(() => {
  console.log('Mongo Db Connected Successfully');
});

app.listen(PORT, () => {
  console.log('Server Running on PORT', PORT);
});
