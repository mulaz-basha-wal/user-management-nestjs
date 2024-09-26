// import { PassportStrategy } from '@nestjs/passport';

// import { ExtractJwt, Strategy } from 'passport-jwt';

// import { StrategiesEnum } from '../constants/strategies.constants';
// import { UserFromJwt } from '../interfaces/auth.interface';
// import { Request } from 'express';

// export class JwtStrategy extends PassportStrategy(
//   Strategy,
//   StrategiesEnum.JWT,
// ) {
//   constructor() {
//     super({
//       jwtFromRequest: ExtractJwt.fromExtractors([
//         (req: Request) => req?.cookies?.['token'] || null,
//       ]),
//       ignoreExpiration: false,
//       secretOrKey: process.env.JWT_SECRET,
//     });
//   }

//   async validate(payload: UserFromJwt) {
//     return { userId: payload.id, email: payload.email };
//   }
// }
