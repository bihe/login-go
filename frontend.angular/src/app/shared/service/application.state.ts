import { ReplaySubject } from 'rxjs';
import { UserInfo } from '../models/user.info.model';
import { AppInfo } from './app.info.model';

export class ApplicationState {
    private progress: ReplaySubject<boolean> = new ReplaySubject();
    private appInfo: ReplaySubject<AppInfo> = new ReplaySubject();

    public setAppInfo(data: AppInfo) {
        this.appInfo.next(data);
    }

    public getAppInfo(): ReplaySubject<AppInfo> {
        return this.appInfo;
    }

    public setProgress(data: boolean) {
        this.progress.next(data);
    }

    public getProgress(): ReplaySubject<boolean> {
        return this.progress;
    }
}
