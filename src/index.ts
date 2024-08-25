import Server, { MyRouter } from "./server";
import AuthService from "./auth/service";
import AuthController from "./auth/controller";
import { connect, disconnect } from "./db";
import db from "./db";

const app = new Server(async () => await connect());

{
    const router = new MyRouter()
    const authService = new AuthService(db);
    const authController = new AuthController(router, authService);
    app.router('/api/auth', authController.execute())
}

app.listen(3000, async () => await disconnect());