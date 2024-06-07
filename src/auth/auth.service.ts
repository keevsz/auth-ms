import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';
import { PrismaClient } from '@prisma/client';
import { RpcException } from '@nestjs/microservices';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  async signJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }

  onModuleInit() {
    this.$connect();
    this.logger.log('Connected to database');
  }

  async registerUser(registerDto: RegisterDto) {
    const { email, password, name } = registerDto;
    try {
      const userExists = await this.user.findUnique({
        where: {
          email: email,
        },
      });

      if (userExists) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email: email,
          password: await argon2.hash(password),
          name: name,
        },
      });

      const payload: JwtPayload = {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
      };

      const token = await this.signJwt(payload);

      delete newUser.password;
      return { user: newUser, token };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;
    try {
      const userExists = await this.user.findUnique({
        where: {
          email: email,
        },
      });

      if (!userExists) {
        throw new RpcException({
          status: 400,
          message: 'User not found',
        });
      }

      const passwordMatch = await argon2.verify(userExists.password, password);
      if (!passwordMatch) {
        throw new RpcException({
          status: 400,
          message: 'Incorrect password',
        });
      }

      const payload: JwtPayload = {
        id: userExists.id,
        email: userExists.email,
        name: userExists.name,
      };

      const token = await this.signJwt(payload);

      delete userExists.password;
      return { user: userExists, token };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: error.message,
      });
    }
  }

  async verifyToken(token: string) {
    try {
      const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user,
        token: await this.signJwt(user)
      };
    } catch (error) {
      throw new RpcException({
        status: 400,
        message: 'Invalid token',
      })
    }
  }
}
