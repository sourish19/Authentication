import mongoose from 'mongoose';

class DB {
  constructor() {
    connectDb: this.connectMongo;
  }
  async connectMongo() {
    try {
      const connect = await mongoose.connect(process.env.MONGO_URI);
    } catch (error) {
      console.error('Error occured: ', error);
      process.exit(1);
    }
  }
}

export default DB;
