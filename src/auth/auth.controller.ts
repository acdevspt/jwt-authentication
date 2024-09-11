import { Controller, Request, Post, UseGuards, Get, Body, HttpCode, HttpStatus } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { AtGuard, RtGuard } from './common/guards';
import { GetCurrentUser, GetCurrentUserId, Public } from './common/decorators';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

    @Public()
    @Post('signin')
    @HttpCode(HttpStatus.OK)
    async login(@Body() dto: AuthDto): Promise<Tokens> {
      return this.authService.signin(dto);
    }

    @Public()
    @Post('signup')
    @HttpCode(HttpStatus.CREATED)
    async signup(@Body() dto: AuthDto): Promise<Tokens> {
        return this.authService.signUp(dto);
    }

    @UseGuards(AtGuard)
    @Post('logout')
    @HttpCode(HttpStatus.OK)
    logout(@GetCurrentUserId() userUuid: string) {
        return this.authService.logout(userUuid);
    }

    @Public()
    @UseGuards(RtGuard)
    @Post('refresh')
    @HttpCode(HttpStatus.OK)
    refreshTokens(
      @GetCurrentUserId() userUuid: string, 
      @GetCurrentUser("refreshToken") refreshToken: string
    ) {
        console.log(refreshToken)
        return this.authService.refreshTokens(userUuid, refreshToken);
      }
}
