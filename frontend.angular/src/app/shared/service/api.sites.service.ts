import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { catchError, timeout } from 'rxjs/operators';
import { UserInfo } from '../models/user.info.model';
import { BaseDataService } from './api.base.service';
import { SiteInfo } from '../models/site.info.model';


@Injectable()
export class ApiUserService extends BaseDataService {
  private readonly APP_INFO_URL: string = '/api/v1/sites';

  constructor (private http: HttpClient) {
    super();
  }

  getUserInfo(): Observable<UserInfo> {
    return this.http.get<UserInfo>(this.APP_INFO_URL, this.RequestOptions)
      .pipe(
        timeout(this.RequestTimeOutDefault),
        catchError(this.handleError)
      );
  }

  saveUserInfo(payload: SiteInfo[]): Observable<string> {
    return this.http.post<string>(this.APP_INFO_URL, payload, this.RequestOptions)
      .pipe(
        timeout(this.RequestTimeOutDefault),
        catchError(this.handleError)
      );
  }
}
