import { ForbiddenException, Injectable } from '@nestjs/common';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { jwtConstants } from './constants';
import * as argon from 'argon2';
import { log } from 'console';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private prisma: PrismaService
  ) {}

 /* async validateUser(username: string, pass: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user && user.password === pass) {
      const { password, ...result } = user;
      return result;
    }
    return null;
  }*/

  async signin(dto: AuthDto): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email
      }
    })

    if(!user) {
      throw new ForbiddenException("Access Denied")
    }

    const passwordMatches = await bcrypt.compare(dto.password, user.hash)
    if (!passwordMatches) {
      throw new ForbiddenException("Access Denied")
    }

    const tokens = await this.getTokens(user.uuid, user.email)
    await this.updateRefreshToken(user.uuid, tokens.refresh_tokens)
    return tokens
  } 

  async signUp(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashData(dto.password)
    const newUser = await this.prisma.user.create({
      data: {
        email: dto.email,
        hash
      }
    })

    const tokens = await this.getTokens(newUser.uuid, newUser.email)
    await this.updateRefreshToken(newUser.uuid, tokens.refresh_tokens)
    return tokens
  }

  async logout(userUuid: string) {
    await this.prisma.user.updateMany({
      where: {
        uuid: userUuid,
        hashedRt: {
          not: null
        }
      },
      data: {
        hashedRt: null
      }
    })
  }

  async refreshTokens(userUuid: string, refreshToken: string): Promise<Tokens> {
    const user = await this.prisma.user.findUnique({
      where: {
        uuid: userUuid
      }
    })

    console.log(user)

    if (!user || !user.hashedRt) {
      throw new ForbiddenException("Access Denied")
    }

    console.log(user.hashedRt.toString())
    console.log(refreshToken)

    const refreshTokenMatches = await argon.verify(user.hashedRt, refreshToken)
    if (!refreshTokenMatches) {
      throw new ForbiddenException("Access Denied")
    }

    const tokens = await this.getTokens(user.uuid, user.email)

    console.log(tokens)

    await this.updateRefreshToken(user.uuid, tokens.refresh_tokens)
    return tokens
  }

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async getTokens(userUuid: string, email: string): Promise<Tokens> {
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync({
        sub: userUuid,
        email: email
      }, {
        expiresIn: 15 * 60,
        secret: jwtConstants.secret
      }),

      this.jwtService.signAsync({
        sub: userUuid,
        email: email
      }, {
        expiresIn: 24 * 7 * 60 * 60,
        secret: jwtConstants.secret
      })
    ]);
     return {
      access_tokens: accessToken,
      refresh_tokens: refreshToken
     }
  }

  async updateRefreshToken(userUuid: string, refreshToken: string): Promise<void> {
    //const hash = this.hashData(refreshToken)
    const hash = await argon.hash(refreshToken)
    await this.prisma.user.update({
      where: {
        uuid: userUuid
      },
      data: {
        hashedRt: hash,
      }
    })
  }
}