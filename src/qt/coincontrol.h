#ifndef COINCONTROL_H
#define COINCONTROL_H

#include <QAbstractButton>
#include <QAction>
#include <QDialog>
#include <QKeyEvent>
#include <QList>
#include <QMenu>
#include <QPoint>
#include <QString>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include "wallet.h"

namespace Ui {
    class CoinControl;
}

class WalletModel;
class CCoinControl;

class CoinControl : public QDialog {
    Q_OBJECT

public:
    explicit CoinControl(QWidget *parent = 0);
    ~CoinControl();

    void setModel(WalletModel *model);

    /* static because also called from sendcoinsdialog */
    static void updateLabels(WalletModel *, QDialog *);
    static QString getPriorityLabel(double);

    static QList<qint64> payAmounts;
    static CCoinControl *control;

private:
    Ui::CoinControl *ui;
    WalletModel *model;
    int sortColumn;
    Qt::SortOrder sortOrder;

    QMenu *contextMenu;
    QTreeWidgetItem *contextMenuItem;
    QAction *copyTransactionHashAction;

    QString strPad(QString, int, QString);
    void sortView(int, Qt::SortOrder);
    void updateView();

    enum
    {
        COLUMN_CHECKBOX,
        COLUMN_AMOUNT,
        COLUMN_LABEL,
        COLUMN_ADDRESS,
        COLUMN_DATE,
        COLUMN_CONFIRMATIONS,
        COLUMN_PRIORITY,
        COLUMN_TXHASH,
        COLUMN_VOUT_INDEX,
        COLUMN_AMOUNT_INT64,
        COLUMN_PRIORITY_INT64
    };

private slots:
    void showMenu(const QPoint &);
    void copyAmount();
    void copyLabel();
    void copyAddress();
    void copyTransactionHash();
    void clipboardQuantity();
    void clipboardAmount();
    void clipboardFee();
    void clipboardNetAmount();
    void clipboardBytes();
    void clipboardPriority();
    void clipboardLowOutput();
    void clipboardChange();
    void radioTreeMode(bool);
    void radioListMode(bool);
    void viewItemChanged(QTreeWidgetItem *, int);
    void headerSectionClicked(int);
    void buttonBoxClicked(QAbstractButton *);
    void buttonSelectAllClicked();
};

/* Tree item that sorts numerically on the columns which expose a real value
 * through Qt::UserRole (amount and confirmations) or Qt::UserRole + 1
 * (priority, kept as a double). This replaces the previous behaviour of
 * comparing space-padded display strings, which ordered values wrong once a
 * number exceeded its fixed pad width or overflowed int64. */
class CoinControlTreeWidgetItem : public QTreeWidgetItem {
public:
    explicit CoinControlTreeWidgetItem(int type = QTreeWidgetItem::Type) :
        QTreeWidgetItem(type) {}
    explicit CoinControlTreeWidgetItem(QTreeWidget *parent,
      int type = QTreeWidgetItem::Type) : QTreeWidgetItem(parent, type) {}
    explicit CoinControlTreeWidgetItem(QTreeWidgetItem *parent,
      int type = QTreeWidgetItem::Type) : QTreeWidgetItem(parent, type) {}

    virtual bool operator<(const QTreeWidgetItem &other) const;
};

class CoinControlTreeWidget : public QTreeWidget {
    Q_OBJECT

public:
    explicit CoinControlTreeWidget(QWidget *parent = 0);

protected:
    virtual void keyPressEvent(QKeyEvent *event);
};

#endif /* COINCONTROL_H */
